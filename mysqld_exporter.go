/*
 * @Notice: edit notice here
 * @Author: zhulei
 * @Date: 2022-07-29 13:18:37
 * @LastEditors: zhulei
 * @LastEditTime: 2022-08-03 15:16:47
 */
// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"github.com/spf13/viper"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/ini.v1"

	"github.com/prometheus/mysqld_exporter/collector"
)

var (
	webConfig     = webflag.AddFlags(kingpin.CommandLine)
	listenAddress = kingpin.Flag(
		"web.listen-address",
		"Address to listen on for web interface and telemetry.",
	).Default(":9104").String()
	metricPath = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Default("/metrics").String()
	timeoutOffset = kingpin.Flag(
		"timeout-offset",
		"Offset to subtract from timeout in seconds.",
	).Default("0.25").Float64()
	configMycnf = kingpin.Flag(
		"config.my-cnf",
		"Path to my.yaml file to read MySQL credentials from.",
	).Default(path.Join(os.Getenv("HOME"), "my.yaml")).String()
	tlsInsecureSkipVerify = kingpin.Flag(
		"tls.insecure-skip-verify",
		"Ignore certificate and server verification when using a tls connection.",
	).Bool()
	dsn       string
	mysqlName string
	cfgFile   string
)

// scrapers lists all possible collection methods and if they should be enabled by default.
var scrapers map[collector.Scraper]bool

type Config struct {
	Name string
}

// 读取配置
func (c *Config) InitConfig() error {
	if c.Name != "" {
		viper.SetConfigFile(c.Name)
	} else {
		viper.AddConfigPath("./")
		viper.SetConfigName("my")
	}
	viper.SetConfigType("yaml")

	// 从环境变量中读取
	viper.AutomaticEnv()
	viper.SetEnvPrefix("web")
	viper.SetEnvKeyReplacer(strings.NewReplacer("_", "."))

	return viper.ReadInConfig()
}

// 初始化配置
func initConfig() {
	c := Config{
		Name: cfgFile,
	}

	if err := c.InitConfig(); err != nil {
		panic(err)
	}
	fmt.Println("载入配置成功")
}

// func parseMyYaml(configName string) map[string]interface{} {
// 	host := viper.GetStringMap("host")
// 	return host
// }

func parseMycnf(config interface{}) (string, error) {
	var dsn string
	opts := ini.LoadOptions{
		// MySQL ini file can have boolean keys.
		AllowBooleanKeys: true,
	}
	cfg, err := ini.LoadSources(opts, config)
	if err != nil {
		return dsn, fmt.Errorf("failed reading ini file: %s", err)
	}
	user := cfg.Section("client").Key("user").String()
	password := cfg.Section("client").Key("password").String()
	if user == "" {
		return dsn, fmt.Errorf("no user specified under [client] in %s", config)
	}

	name := cfg.Section("client").Key("name").MustString("localhost")
	host := cfg.Section("client").Key("host").MustString("localhost")
	port := cfg.Section("client").Key("port").MustUint(3306)
	socket := cfg.Section("client").Key("socket").String()
	sslCA := cfg.Section("client").Key("ssl-ca").String()
	sslCert := cfg.Section("client").Key("ssl-cert").String()
	sslKey := cfg.Section("client").Key("ssl-key").String()
	passwordPart := ""
	if password != "" {
		passwordPart = ":" + password
	} else {
		if sslKey == "" {
			return dsn, fmt.Errorf("password or ssl-key should be specified under [client] in %s", config)
		}
	}
	if socket != "" {
		dsn = fmt.Sprintf("%s%s@unix(%s)/", user, passwordPart, socket)
	} else {
		dsn = fmt.Sprintf("%s%s@tcp(%s:%d)/", user, passwordPart, host, port)
	}
	if sslCA != "" {
		if tlsErr := customizeTLS(sslCA, sslCert, sslKey); tlsErr != nil {
			tlsErr = fmt.Errorf("failed to register a custom TLS configuration for mysql dsn: %s", tlsErr)
			return dsn, tlsErr
		}
		dsn = fmt.Sprintf("%s?tls=custom", dsn)
	}
	mysqlName = name
	return dsn, nil
}

func customizeTLS(sslCA string, sslCert string, sslKey string) error {
	var tlsCfg tls.Config
	caBundle := x509.NewCertPool()
	pemCA, err := os.ReadFile(sslCA)
	if err != nil {
		return err
	}
	if ok := caBundle.AppendCertsFromPEM(pemCA); ok {
		tlsCfg.RootCAs = caBundle
	} else {
		return fmt.Errorf("failed parse pem-encoded CA certificates from %s", sslCA)
	}
	if sslCert != "" && sslKey != "" {
		certPairs := make([]tls.Certificate, 0, 1)
		keypair, err := tls.LoadX509KeyPair(sslCert, sslKey)
		if err != nil {
			return fmt.Errorf("failed to parse pem-encoded SSL cert %s or SSL key %s: %s",
				sslCert, sslKey, err)
		}
		certPairs = append(certPairs, keypair)
		tlsCfg.Certificates = certPairs
	}
	tlsCfg.InsecureSkipVerify = *tlsInsecureSkipVerify
	mysql.RegisterTLSConfig("custom", &tlsCfg)
	return nil
}

func init() {
	prometheus.MustRegister(version.NewCollector("mysqld_exporter"))
}

func newHandler(metrics collector.Metrics, scrapers []collector.Scraper, logger log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()["name"]
		// collector.HostLableValue = params[0]
		// Use request context for cancellation when connection gets closed.
		ctx := r.Context()
		// If a timeout is configured via the Prometheus header, add it to the context.
		if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
			timeoutSeconds, err := strconv.ParseFloat(v, 64)
			if err != nil {
				level.Error(logger).Log("msg", "Failed to parse timeout from Prometheus header", "err", err)
			} else {
				if *timeoutOffset >= timeoutSeconds {
					// Ignore timeout offset if it doesn't leave time to scrape.
					level.Error(logger).Log("msg", "Timeout offset should be lower than prometheus scrape timeout", "offset", *timeoutOffset, "prometheus_scrape_timeout", timeoutSeconds)
				} else {
					// Subtract timeout offset from timeout.
					timeoutSeconds -= *timeoutOffset
				}
				// Create new timeout context with request context as parent.
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds*float64(time.Second)))
				defer cancel()
				// Overwrite request with timeout context.
				r = r.WithContext(ctx)
			}
		}
		level.Info(logger).Log("msg", "collect[] params", "params", strings.Join(params, ","))

		// Check if we have some "collect[]" query parameters.
		// if len(params) > 0 {
		// 	filters := make(map[string]bool)
		// 	for _, param := range params {
		// 		filters[param] = true
		// 	}

		// filteredScrapers := scrapers
		// filteredScrapers = nil

		// for _, scraper := range scrapers {
		// 	if filters[scraper.Name()] {
		// 		filteredScrapers = append(filteredScrapers, scraper)
		// 	}
		// }
		// }
		host := viper.GetStringMap(fmt.Sprintf("host.%s", params[0]))

		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/", host["user"], host["pwd"], host["ip"], host["port"])

		// for k,v range host {
		// 	dsn = fmt.Sprintf("%s%s@tcp(%s:%d)/", user, passwordPart, host, port)
		// }

		registry := prometheus.NewRegistry()
		registry.MustRegister(collector.New(ctx, dsn, metrics, scrapers, logger))

		gatherers := prometheus.Gatherers{
			prometheus.DefaultGatherer,
			registry,
		}
		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
	}
}

func main() {

	// Parse flags.
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("mysqld_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	cfgFile = *configMycnf
	fmt.Println(cfgFile)
	initConfig()
	scrapers = map[collector.Scraper]bool{
		collector.ScrapeGlobalStatus{}:                        viper.GetBool("global_status"),
		collector.ScrapeGlobalVariables{}:                     viper.GetBool("global_variables"),
		collector.ScrapeSlaveStatus{}:                         viper.GetBool("slave_status"),
		collector.ScrapeProcesslist{}:                         viper.GetBool("processlist"),
		collector.ScrapeUser{}:                                viper.GetBool("mysql_user"),
		collector.ScrapeTableSchema{}:                         viper.GetBool("table_schema"),
		collector.ScrapeInfoSchemaInnodbTablespaces{}:         viper.GetBool("innodb_tablespaces"),
		collector.ScrapeInnodbMetrics{}:                       viper.GetBool("innodb_metrics"),
		collector.ScrapeAutoIncrementColumns{}:                viper.GetBool("auto_increment_columns"),
		collector.ScrapeBinlogSize{}:                          viper.GetBool("binlog_size"),
		collector.ScrapePerfTableIOWaits{}:                    viper.GetBool("table_io_waits"),
		collector.ScrapePerfIndexIOWaits{}:                    viper.GetBool("index_io_waits"),
		collector.ScrapePerfTableLockWaits{}:                  viper.GetBool("table_locks"),
		collector.ScrapePerfEventsStatements{}:                viper.GetBool("events_statements"),
		collector.ScrapePerfEventsStatementsSum{}:             viper.GetBool("events_statements_sum"),
		collector.ScrapePerfEventsWaits{}:                     viper.GetBool("events_waits"),
		collector.ScrapePerfFileEvents{}:                      viper.GetBool("file_events"),
		collector.ScrapePerfFileInstances{}:                   viper.GetBool("file_instances"),
		collector.ScrapePerfMemoryEvents{}:                    viper.GetBool("memory_events"),
		collector.ScrapePerfReplicationGroupMembers{}:         viper.GetBool("replication_group_members"),
		collector.ScrapePerfReplicationGroupMemberStats{}:     viper.GetBool("replication_group_member_stats"),
		collector.ScrapePerfReplicationApplierStatsByWorker{}: viper.GetBool("replication_applier_status_by_worker"),
		collector.ScrapeUserStat{}:                            viper.GetBool("user_stats"),
		collector.ScrapeClientStat{}:                          viper.GetBool("client_stats"),
		collector.ScrapeTableStat{}:                           viper.GetBool("table_stats"),
		collector.ScrapeSchemaStat{}:                          viper.GetBool("schema_stats"),
		collector.ScrapeInnodbCmp{}:                           viper.GetBool("innodb_cmp"),
		collector.ScrapeInnodbCmpMem{}:                        viper.GetBool("innodb_cmp_mem"),
		collector.ScrapeQueryResponseTime{}:                   viper.GetBool("query_response_time"),
		collector.ScrapeEngineTokudbStatus{}:                  viper.GetBool("engine_tokudb_status"),
		collector.ScrapeEngineInnodbStatus{}:                  viper.GetBool("engine_innodb_status"),
		collector.ScrapeHeartbeat{}:                           viper.GetBool("heartbeat"),
		collector.ScrapeSlaveHosts{}:                          viper.GetBool("slave_hosts"),
		collector.ScrapeReplicaHost{}:                         viper.GetBool("replica_host"),
	}

	// Generate ON/OFF flags for all scrapers.
	// scraperFlags := map[collector.Scraper]*bool{}
	// for scraper, enabledByDefault := range scrapers {
	// 	// defaultOn := "false"

	// 	if enabledByDefault {
	// 		// defaultOn = "true"
	// 		level.Info(logger).Log(scraper.Name())
	// 	}

	// 	// f := kingpin.Flag(
	// 	// 	"collect."+scraper.Name(),
	// 	// 	scraper.Help(),
	// 	// ).Default(defaultOn).Bool()

	// 	scraperFlags[scraper] = &enabledByDefault
	// }

	// landingPage contains the HTML served at '/'.
	// TODO: Make this nicer and more informative.
	var landingPage = []byte(`<html>
<head><title>MySQLd exporter</title></head>
<body>
<h1>MySQLd exporter</h1>
<p><a href='` + *metricPath + `'>Metrics</a></p>
</body>
</html>
`)

	level.Info(logger).Log("msg", "Starting mysqld_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", version.BuildContext())

	// dsn = os.Getenv("DATA_SOURCE_NAME")
	// if len(dsn) == 0 {
	// 	var err error
	// 	if dsn, err = parseMycnf(*configMycnf); err != nil {
	// 		level.Info(logger).Log("msg", "Error parsing my.cnf", "file", *configMycnf, "err", err)
	// 		os.Exit(1)
	// 	}
	// }

	// Register only scrapers enabled by flag.
	enabledScrapers := []collector.Scraper{}
	for scraper, enabled := range scrapers {
		if enabled {
			level.Info(logger).Log("msg", "Scraper enabled", "scraper", scraper.Name())
			enabledScrapers = append(enabledScrapers, scraper)
		}
	}
	handlerFunc := newHandler(collector.NewMetrics(), enabledScrapers, logger)
	http.Handle(*metricPath, promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, handlerFunc))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(landingPage)
	})

	level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
	srv := &http.Server{Addr: *listenAddress}
	if err := web.ListenAndServe(srv, *webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
