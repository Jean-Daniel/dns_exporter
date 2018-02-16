package main

import (
	"net/http"
	"path"
	"runtime"
	"strings"

	"github.com/Jean-Daniel/dns_exporter/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

type protocolMetric struct {
	name string
	desc *prometheus.Desc
}

func (m *protocolMetric) Desc() *prometheus.Desc {
	return m.desc
}

func (m *protocolMetric) Match(name string, value float64, ch chan<- prometheus.Metric) bool {
	if name == m.name || name == m.name+"6" {
		protocol := "ipv4"
		if strings.HasSuffix(name, "6") {
			protocol = "ipv6"
		}
		ch <- prometheus.MustNewConstMetric(m.desc, prometheus.CounterValue, value, protocol)
		return true
	}
	return false
}

func newProtocolMetric(name string, metric string, description string) utils.MatchMetric {
	return &protocolMetric{
		name: name,
		desc: prometheus.NewDesc(prometheus.BuildFQName("nsd", "", metric), description, []string{"protocol"}, nil),
	}
}

var (
	simpleMetrics = map[string]utils.SimpleMetric{
		"time.boot":    newNsdSimpleMetrics("time_up_seconds_total", "Time since server boot in seconds.", prometheus.CounterValue),
		"time.elapsed": newNsdSimpleMetrics("time_elapsed_seconds", "Time since the last stats report, in seconds.", prometheus.GaugeValue),

		"size.db.disk":  newNsdSimpleMetrics("db_size_disk_bytes", "Size of nsd.db on disk, in bytes.", prometheus.GaugeValue),
		"size.db.mem":   newNsdSimpleMetrics("db_size_mem_bytes", "Size of the DNS database in memory, in bytes.", prometheus.GaugeValue),
		"size.xfrd.mem": newNsdSimpleMetrics("xfrd_size_mem_bytes", "Size of the DNS database in memory, in bytes.", prometheus.GaugeValue),

		"size.config.disk": newNsdSimpleMetrics("zone_size_disk_bytes", "Size of zonelist file on disk, excludes the nsd.conf size, in bytes.", prometheus.GaugeValue),
		"size.config.mem":  newNsdSimpleMetrics("zone_size_mem_bytes", "Size of zonelist file in memory, kept twice in server and xfrd process, in bytes.", prometheus.GaugeValue),

		"num.edns":    newNsdSimpleMetrics("queries_edns_total", "Number of queries with EDNS OPT.", prometheus.CounterValue),
		"num.ednserr": newNsdSimpleMetrics("queries_edns_err_total", "Number of queries which failed EDNS parse.", prometheus.CounterValue),

		// num.tcp
		"num.answer_wo_aa": newNsdSimpleMetrics("answer_without_aa_total", "Number of answers with NOERROR rcode and without AA flag.", prometheus.CounterValue),
		"num.rxerr":        newNsdSimpleMetrics("queries_err_total", "Number of queries for which the receive failed.", prometheus.CounterValue),
		"num.txerr":        newNsdSimpleMetrics("answer_err_total", "Number of answers for which the transmit failed.", prometheus.CounterValue),
		"num.raxfr":        newNsdSimpleMetrics("queries_axfr_total", "Number of AXFR requests from clients (that got served with reply).", prometheus.CounterValue),
		"num.truncated":    newNsdSimpleMetrics("answer_truncated_total", "Number of answers with TC flag set.", prometheus.CounterValue),
		"num.dropped":      newNsdSimpleMetrics("queries_dropped_total", "Number of queries that were dropped because they failed sanity check.", prometheus.CounterValue),

		"zone.master": newNsdSimpleMetrics("zones_master", "Number of master zones served.", prometheus.GaugeValue),
		"zone.slave":  newNsdSimpleMetrics("zones_slave", "Number of slave zones served.", prometheus.GaugeValue),
	}

	regexMetrics = []utils.MatchMetric{
		newProtocolMetric("num.udp", "queries_udp_total", "Number of queries over UDP."),
		newProtocolMetric("num.tcp", "queries_tcp_total", "Number of queries over TCP."),

		newNsdRegexMetric("queries_total",
			"Total number of queries received.",
			prometheus.CounterValue,
			[]string{"server"}, "^server(\\d+)\\.queries$"),
		// num.type.X
		newNsdRegexMetric("query_type_total",
			"Total number of queries with a given type.",
			prometheus.CounterValue,
			[]string{"type"}, "^num\\.type\\.([\\w]+)$"),
		// num.opcode.X
		newNsdRegexMetric("query_opcode_total",
			"Total number of queries with a given opcode.",
			prometheus.CounterValue,
			[]string{"opcode"}, "^num\\.opcode\\.([\\w]+)$"),
		// num.class.X
		newNsdRegexMetric("query_class_total",
			"Total number of queries with a given class.",
			prometheus.CounterValue,
			[]string{"class"}, "^num\\.class\\.([\\w]+)$"),
		// num.rcode.X
		newNsdRegexMetric("query_rcode_total",
			"Total number of queries with a given rcode.",
			prometheus.CounterValue,
			[]string{"rcode"}, "^num\\.rcode\\.([\\w]+)$"),
	}
)

func newNsdSimpleMetrics(name string, description string, valueType prometheus.ValueType) utils.SimpleMetric {
	return utils.NewSimpleMetric("nsd", name, description, valueType)
}

func newNsdRegexMetric(name string, description string, valueType prometheus.ValueType, labels []string, pattern string) utils.MatchMetric {
	return utils.NewRegexMetric("nsd", name, description, valueType, labels, pattern)
}

func main() {
	nsdPrefix := "/etc/nsd"
	if runtime.GOOS == "openbsd" {
		nsdPrefix = "/var/nsd/etc"
	}
	var (
		listenAddress = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9168").String()
		metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		controlHost   = kingpin.Flag("nsd.host", "NSD control socket hostname and port number (or absolute path).").Default("localhost:8952").String()
		controlCa     = kingpin.Flag("nsd.ca", "Unbound server certificate.").Default(path.Join(nsdPrefix, "nsd_server.pem")).String()
		controlCert   = kingpin.Flag("nsd.cert", "Unbound client certificate.").Default(path.Join(nsdPrefix, "nsd_control.pem")).String()
		controlKey    = kingpin.Flag("nsd.key", "Unbound client key.").Default(path.Join(nsdPrefix, "nsd_control.key")).String()
	)
	kingpin.Parse()

	log.Info("Starting nsd_exporter")
	exporter, err := utils.NewMetricExporter("nsd", "NSDCT1", *controlHost, *controlCa, *controlCert, *controlKey, simpleMetrics, regexMetrics, nil)
	if err != nil {
		panic(err)
	}
	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, prometheus.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
			<html>
			<head><title>NSD Exporter</title></head>
			<body>
			<h1>NSD Exporter</h1>
			<p><a href='` + *metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
	})
	log.Info("Listening on address:port => ", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
