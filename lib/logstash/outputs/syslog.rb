# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "date"


# Send events to a syslog server.
#
# You can send messages compliant with RFC3164 or RFC5424
# using either UDP or TCP as the transport protocol.
#
# By default the contents of the `message` field will be shipped as
# the free-form message text part of the emitted syslog message. If
# your messages don't have a `message` field or if you for some other
# reason want to change the emitted message, modify the `message`
# configuration option.
class LogStash::Outputs::Syslog < LogStash::Outputs::Base
  config_name "syslog"

  FACILITY_LABELS = [
    "kernel",
    "user-level",
    "mail",
    "daemon",
    "security/authorization",
    "syslogd",
    "line printer",
    "network news",
    "uucp",
    "clock",
    "security/authorization",
    "ftp",
    "ntp",
    "log audit",
    "log alert",
    "clock",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
  ]

  SEVERITY_LABELS = [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "informational",
    "debug",
  ]

  # syslog server address to connect to
  config :host, :validate => :string, :required => true

  # syslog server port to connect to
  config :port, :validate => :number, :required => true

  # when connection fails, retry interval in sec.
  config :reconnect_interval, :validate => :number, :default => 1

  # syslog server protocol. you can choose between udp and tcp
  config :protocol, :validate => ["tcp", "udp"], :default => "udp"

  # use label parsing for severity and facility levels
  # use priority field if set to false
  config :use_labels, :validate => :boolean, :default => true

  # syslog priority
  # The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :priority, :validate => :string, :default => "%{syslog_pri}"

  # facility label for syslog message
  # default fallback to user-level as in rfc3164
  # The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :facility, :validate => :string, :default => "user-level"

  # severity label for syslog message
  # default fallback to notice as in rfc3164
  # The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :severity, :validate => :string, :default => "notice"

  # source host for syslog message. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :sourcehost, :validate => :string, :default => "%{host}"

  # timestamp for syslog message
  config :timestamp, :validate => :string, :default => "%{@timestamp}", :deprecated => "This setting is no longer necessary. The RFC setting will determine what time format is used."

  # application name for syslog message. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :appname, :validate => :string, :default => "LOGSTASH"

  # process id for syslog message. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :procid, :validate => :string, :default => "-"

  # message text to log. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :message, :validate => :string, :default => "%{message}"

  # message id for syslog message. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :msgid, :validate => :string, :default => "-"

  # syslog message format: you can choose between rfc3164 or rfc5424
  config :rfc, :validate => ["rfc3164", "rfc5424"], :default => "rfc3164"

  def register
    @client_socket = nil

    # use instance variable to avoid string comparison for each event
    @is_rfc3164 = (@rfc == "rfc3164")
  end

  def receive(event)
    appname = event.sprintf(@appname)
    procid = event.sprintf(@procid)
    sourcehost = event.sprintf(@sourcehost)

    # fallback to pri 13 (facility 1, severity 5)
    if @use_labels
      facility_code = (FACILITY_LABELS.index(event.sprintf(@facility)) || 1)
      severity_code = (SEVERITY_LABELS.index(event.sprintf(@severity)) || 5)
      priority = (facility_code * 8) + severity_code
    else
      priority = Integer(event.sprintf(@priority)) rescue 13
      priority = 13 if (priority < 0 || priority > 191)
    end

    if @is_rfc3164
      timestamp = event.sprintf("%{+MMM dd HH:mm:ss}")
      syslog_msg = "<#{priority.to_s}>#{timestamp} #{sourcehost} #{appname}[#{procid}]: #{event.sprintf(@message)}"
    else
      msgid = event.sprintf(@msgid)
      timestamp = event.sprintf("%{+YYYY-MM-dd'T'HH:mm:ss.SSSZZ}")
      syslog_msg = "<#{priority.to_s}>1 #{timestamp} #{sourcehost} #{appname} #{procid} #{msgid} - #{event.sprintf(@message)}"
    end

    begin
      @client_socket ||= connect
      @client_socket.write(syslog_msg + "\n")
    rescue => e
      # We don't expect udp connections to fail because they are stateless, but ...
      # udp connections may fail/raise an exception if used with localhost/127.0.0.1
      return if udp?

      @logger.warn("syslog " + @protocol + " output exception: closing, reconnecting and resending event", :host => @host, :port => @port, :exception => e, :backtrace => e.backtrace, :event => event)
      @client_socket.close rescue nil
      @client_socket = nil

      sleep(@reconnect_interval)
      retry
    end
  end

  private

  def udp?
    @protocol == "udp"
  end

  def connect
    socket = nil
    if udp?
      socket = UDPSocket.new
      socket.connect(@host, @port)
    else
      socket = TCPSocket.new(@host, @port)
    end
    socket
  end
end
