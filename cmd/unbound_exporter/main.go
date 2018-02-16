package main

import (
	"net/http"
	"path"
	"runtime"

	"github.com/Jean-Daniel/dns_exporter/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	/*
		unboundHistogram = prometheus.NewDesc(
			prometheus.BuildFQName("unbound", "", "response_time_seconds"),
			"Query response time in seconds.",
			nil, nil)
	*/

	simpleMetrics = map[string]utils.SimpleMetric{
		"total.recursion.time.avg": newSimpleMetric(
			"recursion_time_seconds_avg",
			"Average time it took to answer queries that needed recursive processing (does not include in-cache requests).",
			prometheus.GaugeValue),
		"total.recursion.time.median": newSimpleMetric(
			"recursion_time_seconds_median",
			"The median of the time it took to answer queries that needed recursive processing.",
			prometheus.GaugeValue),

		"time.now": newSimpleMetric(
			"time_now_seconds",
			"Current time in seconds since 1970.",
			prometheus.GaugeValue),
		"time.up": newSimpleMetric(
			"time_up_seconds_total",
			"Uptime since server boot in seconds.",
			prometheus.CounterValue),
		"time.elapsed": newSimpleMetric(
			"time_elapsed_seconds",
			"Time since last statistics printout in seconds.",
			prometheus.CounterValue),

		// -- Extended stats --
		"num.query.ipv6": newSimpleMetric(
			"query_ipv6_total",
			"Total number of queries that were made using IPv6 towards the Unbound server.",
			prometheus.CounterValue),
		"num.query.tcp": newSimpleMetric(
			"query_tcp_total",
			"Total number of queries that were made using TCP towards the Unbound server.",
			prometheus.CounterValue),
		// num.query.tcpout

		"num.query.edns.present": newSimpleMetric(
			"query_edns_present_total",
			"Total number of queries that had an EDNS OPT record present.",
			prometheus.CounterValue),
		"num.query.edns.DO": newSimpleMetric(
			"query_edns_DO_total",
			"Total number of queries that had an EDNS OPT record with the DO (DNSSEC OK) bit set present.",
			prometheus.CounterValue),
		// num.query.ratelimited
		// num.query.dnscrypt.shared_secret.cachemiss
		// num.query.dnscrypt.replay

		"num.answer.secure": newSimpleMetric(
			"answers_secure_total",
			"Total number of answers that were secure.",
			prometheus.CounterValue),
		"num.answer.bogus": newSimpleMetric(
			"answers_bogus",
			"Total number of answers that were bogus.",
			prometheus.CounterValue),
		"num.rrset.bogus": newSimpleMetric(
			"rrset_bogus_total",
			"Total number of rrsets marked bogus by the validator.",
			prometheus.CounterValue),
		"unwanted.queries": newSimpleMetric(
			"unwanted_queries_total",
			"Total number of queries that were refused or dropped because they failed the access control settings.",
			prometheus.CounterValue),
		"unwanted.replies": newSimpleMetric(
			"unwanted_replies_total",
			"Total number of replies that were unwanted or unsolicited.",
			prometheus.CounterValue),
		// msg.cache.count
		// rrset.cache.count
		// infra.cache.count
		// key.cache.count
		// dnscrypt_shared_secret.cache.count
		// dnscrypt_nonce.cache.count
	}

	regexMetrics = []utils.MatchMetric{
		newRegexMetric(
			"queries_total",
			"Total number of queries received.",
			prometheus.CounterValue,
			[]string{"thread"},
			"^thread(\\d+)\\.num\\.queries$"),
		newRegexMetric(
			"queries_rate_limited_total",
			"Total number of queries rate limited received.",
			prometheus.CounterValue,
			[]string{"thread"},
			"^thread(\\d+)\\.num\\.queries_ip_ratelimited$"),
		newRegexMetric(
			"cache_hits_total",
			"Total number of queries that were successfully answered using a cache lookup.",
			prometheus.CounterValue,
			[]string{"thread"},
			"^thread(\\d+)\\.num\\.cachehits$"),
		newRegexMetric(
			"cache_misses_total",
			"Total number of cache queries that needed recursive processing.",
			prometheus.CounterValue,
			[]string{"thread"},
			"^thread(\\d+)\\.num\\.cachemiss$"),
		// threadX.num.dnscrypt.*
		newRegexMetric(
			"prefetches_total",
			"Total number of cache prefetches performed.",
			prometheus.CounterValue,
			[]string{"thread"},
			"^thread(\\d+)\\.num\\.prefetch$"),
		newRegexMetric(
			"zero_ttl_total",
			"Total number of replies with ttl zero, because they served an expired cache entry.",
			prometheus.CounterValue,
			[]string{"thread"},
			"^thread(\\d+)\\.num\\.zero_ttl$"),
		newRegexMetric(
			"recursive_replies_total",
			"Total number of replies sent to queries that needed recursive processing.",
			prometheus.CounterValue,
			[]string{"thread"},
			"^thread(\\d+)\\.num\\.recursivereplies$"),
		// Request List
		// threadX.requestlist.avg
		// threadX.requestlist.max
		newRegexMetric(
			"request_list_overwritten_total",
			"Total number of requests in the request list that were overwritten by newer entries.",
			prometheus.CounterValue,
			[]string{"thread"},
			"^thread([0-9]+)\\.requestlist\\.overwritten$"),
		newRegexMetric(
			"request_list_exceeded_total",
			"Number of queries that were dropped because the request list was full.",
			prometheus.CounterValue,
			[]string{"thread"},
			"^thread([0-9]+)\\.requestlist\\.exceeded$"),
		newRegexMetric(
			"request_list_current_all",
			"Current size of the request list, including internally generated queries.",
			prometheus.GaugeValue,
			[]string{"thread"},
			"^thread([0-9]+)\\.requestlist\\.current\\.all$"),
		newRegexMetric(
			"request_list_current_user",
			"Current size of the request list, only counting the requests from client queries.",
			prometheus.GaugeValue,
			[]string{"thread"},
			"^thread([0-9]+)\\.requestlist\\.current\\.user$"),
		// threadX.recursion.time.avg
		// threadX.recursion.time.median
		// threadX.tcpusage
		newRegexMetric(
			"tcp_buffers_usage",
			"The currently held tcp buffers for incoming connections.",
			prometheus.GaugeValue,
			[]string{"thread"},
			"^thread([0-9]+)\\.tcpusage$"),

		// -- Extended stats --
		// mem.cache.rrset
		// mem.cache.message
		// mem.cache.dnscrypt_shared_secret
		// mem.cache.dnscrypt_nonce
		newRegexMetric(
			"memory_caches_bytes",
			"Memory in bytes in use by caches.",
			prometheus.GaugeValue,
			[]string{"cache"},
			"^mem\\.cache\\.(\\w+)$"),

		// mem.mod.iterator
		// mem.mod.validator
		newRegexMetric(
			"memory_modules_bytes",
			"Memory in bytes in use by modules.",
			prometheus.GaugeValue,
			[]string{"module"},
			"^mem\\.mod\\.(\\w+)$"),

		// histogram.<sec>.<usec>.to.<sec>.<usec>

		// num.query.type.*
		// num.query.type.other
		newRegexMetric(
			"query_types_total",
			"Total number of queries with a given query type.",
			prometheus.CounterValue,
			[]string{"type"},
			"^num\\.query\\.type\\.([\\w]+)$"),

		// num.query.class.*
		newRegexMetric(
			"query_classes_total",
			"Total number of queries with a given query class.",
			prometheus.CounterValue,
			[]string{"class"},
			"^num\\.query\\.class\\.([\\w]+)$"),

		// num.query.opcode.QUERY
		newRegexMetric(
			"query_opcodes_total",
			"Total number of queries with a given query opcode.",
			prometheus.CounterValue,
			[]string{"opcode"},
			"^num\\.query\\.opcode\\.([\\w]+)$"),

		// num.query.flags.*
		newRegexMetric(
			"query_flags_total",
			"Total number of queries that had a given flag set in the header.",
			prometheus.CounterValue,
			[]string{"flag"},
			"^num\\.query\\.flags\\.([\\w]+)$"),

		// num.answer.rcode.*
		newRegexMetric(
			"answer_rcodes_total",
			"Total number of answers to queries, from cache or from recursion, by response code.",
			prometheus.CounterValue,
			[]string{"rcode"},
			"^num\\.answer\\.rcode\\.(\\w+)$"),
	}
)

/*
func collectFromReader(file io.Reader, ch chan<- prometheus.Metric) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	histogramPattern := regexp.MustCompile("^histogram\\.\\d+\\.\\d+\\.to\\.(\\d+\\.\\d+)$")

	histogramCount := uint64(0)
	histogramAvg := float64(0)
	histogramBuckets := make(map[float64]uint64)

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "=")
		if len(fields) != 2 {
			return fmt.Errorf(
				"%q is not a valid key-value pair",
				scanner.Text())
		}

		if matches := histogramPattern.FindStringSubmatch(fields[0]); matches != nil {
			end, err := strconv.ParseFloat(matches[1], 64)
			if err != nil {
				return err
			}
			value, err := strconv.ParseUint(fields[1], 10, 64)

			if err != nil {
				return err
			}
			histogramBuckets[end] = value
			histogramCount += value
		} else if fields[0] == "total.recursion.time.avg" {
			value, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return err
			}
			histogramAvg = value
		}
	}

	// Convert the metrics to a cumulative Prometheus histogram.
	// Reconstruct the sum of all samples from the average value
	// provided by Unbound. Hopefully this does not break
	// monotonicity.
	keys := []float64{}
	for k := range histogramBuckets {
		keys = append(keys, k)
	}
	sort.Float64s(keys)
	prev := uint64(0)
	for _, i := range keys {
		histogramBuckets[i] += prev
		prev = histogramBuckets[i]
	}
	ch <- prometheus.MustNewConstHistogram(
		unboundHistogram,
		histogramCount,
		histogramAvg*float64(histogramCount),
		histogramBuckets)

	return scanner.Err()
}
*/

func newSimpleMetric(name string, description string, valueType prometheus.ValueType) utils.SimpleMetric {
	return utils.NewSimpleMetric("unbound", name, description, valueType)
}

func newRegexMetric(name string, description string, valueType prometheus.ValueType, labels []string, pattern string) utils.MatchMetric {
	return utils.NewRegexMetric("unbound", name, description, valueType, labels, pattern)
}

func main() {
	unboundPrefix := "/etc/unbound"
	if runtime.GOOS == "openbsd" {
		unboundPrefix = "/var/unbound/etc"
	}
	var (
		listenAddress = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9167").String()
		metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		controlHost   = kingpin.Flag("unbound.host", "Unbound control socket hostname and port number (or absolute path).").Default("localhost:8953").String()
		controlCa     = kingpin.Flag("unbound.ca", "Unbound server certificate.").Default(path.Join(unboundPrefix, "unbound_server.pem")).String()
		controlCert   = kingpin.Flag("unbound.cert", "Unbound client certificate.").Default(path.Join(unboundPrefix, "unbound_control.pem")).String()
		controlKey    = kingpin.Flag("unbound.key", "Unbound client key.").Default(path.Join(unboundPrefix, "unbound_control.key")).String()
	)
	kingpin.Parse()

	log.Info("Starting unbound_exporter")
	exporter, err := utils.NewMetricExporter("unbound", *controlHost, *controlCa, *controlCert, *controlKey, simpleMetrics, regexMetrics)
	if err != nil {
		panic(err)
	}
	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, prometheus.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
			<html>
			<head><title>Unbound Exporter</title></head>
			<body>
			<h1>Unbound Exporter</h1>
			<p><a href='` + *metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
	})
	log.Info("Listening on address:port => ", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
