## Unreleased
  - Change codec instance comparison [#69](https://github.com/logstash-plugins/logstash-output-syslog/pull/69)
  - Added support for RFC5424 structured data [#67](https://github.com/logstash-plugins/logstash-output-syslog/pull/67)
  - The SNI (Server Name Indication) extension is now used when connecting to syslog server with TLS and `host` is set to FQDN (Fully Qualified Domain Name) [#66](https://github.com/logstash-plugins/logstash-output-syslog/pull/66)
  - Add support for CRL to check for the server certificate is revocation status [#62](https://github.com/logstash-plugins/logstash-output-syslog/pull/62)
  - Support loading of PKCS8 EC private keys [#61](https://github.com/logstash-plugins/logstash-output-syslog/pull/61)

## 3.0.5
  - Docs: Set the default_codec doc attribute.

## 3.0.4
  - Update gemspec summary

## 3.0.3
  - Fix some documentation issues

## 3.0.1
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 3.0.0
 - breaking,config: Remove deprecated `timestamp` config.
 - internal: migrate to Logstash Event API 2.0

## 2.1.5
 - [Internal] test fix to not depend on json order

## 2.1.4
 - [Internal] fix tests

## 2.1.3
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash

## 2.1.2
  - New dependency requirements for logstash-core for the 5.0 release

## 2.1.1
 - Add SSL/TLS support to syslog output plugin (thanks @breml)
 - Added ability to use codecs for this output (thanks @breml)

## 2.1.0
 - reconnect on exception. added basic specs

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0
