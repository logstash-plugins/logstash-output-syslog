## 2.1.1
 - Add SSL/TLS support to syslog output plugin (thanks @breml)
 - Added ability to use codecs for this output (thanks @breml)

## 2.1.0
 - reconnect on exception. added basic specs

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

