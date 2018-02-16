package utils

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

// SimpleMetric define a metric without label and static 'stats' name
type SimpleMetric struct {
	desc      *prometheus.Desc
	valueType prometheus.ValueType
}

// NewSimpleMetric returns a new SimpleMetric
func NewSimpleMetric(ns string, name string, description string, valueType prometheus.ValueType) SimpleMetric {
	return SimpleMetric{
		desc:      prometheus.NewDesc(prometheus.BuildFQName(ns, "", name), description, nil, nil),
		valueType: valueType,
	}
}

// MatchMetric define a metric where multiples stats map to a single metric with labels
type MatchMetric interface {
	Desc() *prometheus.Desc
	// Match return true if the metrics match and can be collected
	Match(name string, value float64, ch chan<- prometheus.Metric) bool
}

// RegexMetric MatchMetric that uses regex to match a metric name and extract labels values
type RegexMetric struct {
	desc      *prometheus.Desc
	valueType prometheus.ValueType
	pattern   *regexp.Regexp
}

// NewRegexMetric returns a new RegexMetric
func NewRegexMetric(ns string, name string, description string, valueType prometheus.ValueType, labels []string, pattern string) MatchMetric {
	return &RegexMetric{
		desc:      prometheus.NewDesc(prometheus.BuildFQName("nsd", "", name), description, labels, nil),
		valueType: valueType,
		pattern:   regexp.MustCompile(pattern),
	}
}

// Desc …
func (m *RegexMetric) Desc() *prometheus.Desc {
	return m.desc
}

// Match uses regex pattern to extract label and collect the resulting value
func (m *RegexMetric) Match(name string, value float64, ch chan<- prometheus.Metric) bool {
	if matches := m.pattern.FindStringSubmatch(name); matches != nil {
		ch <- prometheus.MustNewConstMetric(
			m.desc,
			m.valueType,
			value,
			matches[1:]...)
		return true
	}
	return false
}

// MetricsExporter …
type MetricsExporter struct {
	host          string
	tlsConfig     tls.Config
	matchMetrics  []MatchMetric
	simpleMetrics map[string]SimpleMetric
	upDesc        *prometheus.Desc
}

// NewMetricExporter …
func NewMetricExporter(name string, host string, ca string, cert string, key string, simpleMetrics map[string]SimpleMetric, matchMetrics []MatchMetric) (*MetricsExporter, error) {
	/* Server authentication. */
	caData, err := ioutil.ReadFile(ca)
	if err != nil {
		return &MetricsExporter{}, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caData) {
		return &MetricsExporter{}, fmt.Errorf("Failed to parse CA")
	}

	/* Client authentication. */
	certData, err := ioutil.ReadFile(cert)
	if err != nil {
		return &MetricsExporter{}, err
	}
	keyData, err := ioutil.ReadFile(key)
	if err != nil {
		return &MetricsExporter{}, err
	}
	keyPair, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return &MetricsExporter{}, err
	}

	return &MetricsExporter{
		host: host,
		tlsConfig: tls.Config{
			Certificates: []tls.Certificate{keyPair},
			RootCAs:      roots,
			ServerName:   name,
		},
		upDesc:        prometheus.NewDesc(prometheus.BuildFQName(name, "", "up"), "Whether scraping metrics was successful.", nil, nil),
		matchMetrics:  matchMetrics,
		simpleMetrics: simpleMetrics,
	}, nil
}

func (m *MetricsExporter) collectFromReader(file io.Reader, ch chan<- prometheus.Metric) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "=")
		if len(fields) != 2 {
			return fmt.Errorf(
				"%q is not a valid key-value pair",
				scanner.Text())
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			log.Errorf("Failed to parse '%s' metric value: %s", fields[0], err)
			continue
		}

		// 1. lookup simple metric map
		metric, ok := m.simpleMetrics[fields[0]]
		if ok {
			ch <- prometheus.MustNewConstMetric(metric.desc, metric.valueType, value)
			continue
		}

		// 2. try regexp metrics
		for _, metric := range m.matchMetrics {
			if metric.Match(fields[0], value, ch) {
				break
			}
		}
	}

	return scanner.Err()
}

func (m *MetricsExporter) collectFromSocket(ch chan<- prometheus.Metric) error {
	family := "tcp"
	if strings.HasPrefix(m.host, "/") {
		family = "unix"
	}
	conn, err := tls.Dial(family, m.host, &m.tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("UBCT1 stats_noreset\n"))
	if err != nil {
		return err
	}
	return m.collectFromReader(conn, ch)
}

// Describe …
func (m *MetricsExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.upDesc
	for _, metric := range m.simpleMetrics {
		ch <- metric.desc
	}
	for _, metric := range m.matchMetrics {
		ch <- metric.Desc()
	}
}

// Collect …
func (m *MetricsExporter) Collect(ch chan<- prometheus.Metric) {
	err := m.collectFromSocket(ch)
	if err == nil {
		ch <- prometheus.MustNewConstMetric(m.upDesc, prometheus.GaugeValue, 1.0)
	} else {
		log.Errorf("Failed to scrape socket: %s", err)
		ch <- prometheus.MustNewConstMetric(m.upDesc, prometheus.GaugeValue, 0.0)
	}
}
