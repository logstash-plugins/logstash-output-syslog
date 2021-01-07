# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "date"
require "logstash/codecs/plain"


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
    "ftp",
    "ntp",
    "log audit",
    "log alert",
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
  
  # Backup syslog servers to connect to
  config :backuphosts, :validate => :array, :required => false 
  
  # when connection fails, retry interval in sec.
  config :reconnect_interval, :validate => :number, :default => 1
  
  # Resend messages that fail to next available backup host,if true distribute and loadbalance will be set to false.
  config :backup, :validate => :boolean, :default => false

  # Load Balance all configured Hosts(host and backuphosts),if true backup and distribute will be set to false.
  config :loadbalance, :validate => :boolean, :default => false
  
  # Duplicate messages to all configured Hosts(host and backuphosts),if true backup and loadbalance will be set to false.
  config :distribute, :validate => :boolean, :default => false

  # when connection fails, retry amount of times.
  config :reconnect_count, :validate => :number, :default => 2

  # syslog server protocol. you can choose between udp, tcp and ssl/tls over tcp
  config :protocol, :validate => ["tcp", "udp", "ssl-tcp"], :default => "udp"

  # Verify the identity of the other end of the SSL connection against the CA.
  config :ssl_verify, :validate => :boolean, :default => false

  # The SSL CA certificate, chainfile or CA path. The system CA path is automatically included.
  config :ssl_cacert, :validate => :path

  # SSL certificate path
  config :ssl_cert, :validate => :path

  # SSL key path
  config :ssl_key, :validate => :path

  # SSL key passphrase
  config :ssl_key_passphrase, :validate => :password, :default => nil

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
    @host_idx = 0
    @multiconnect_sockets=Hash.new()

    if ssl?
      @ssl_context = setup_ssl
    end
    
    if @codec.instance_of? LogStash::Codecs::Plain
      if @codec.config["format"].nil?
        @codec = LogStash::Codecs::Plain.new({"format" => @message})
      end
    end
    @codec.on_event(&method(:publish))
   	#use instance variable to avoid string comparison for each event
    @is_rfc3164 = (@rfc == "rfc3164")
  end

  def receive(event)
    @codec.encode(event)
  end

  def publish(event, payload)
    appname = event.sprintf(@appname)
    procid = event.sprintf(@procid)
    sourcehost = event.sprintf(@sourcehost)
    message = payload.to_s.rstrip.gsub(/[\r][\n]/, "\n").gsub(/[\n]/, '\n')

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
      syslog_msg = "<#{priority.to_s}>#{timestamp} #{sourcehost} #{appname}[#{procid}]: #{message}"
    else
      msgid = event.sprintf(@msgid)
      timestamp = event.sprintf("%{+YYYY-MM-dd'T'HH:mm:ss.SSSZZ}")
      syslog_msg = "<#{priority.to_s}>1 #{timestamp} #{sourcehost} #{appname} #{procid} #{msgid} - #{message}"
    end
    
    @send=true
    @msgsendfail=false
    prihost="#{@host}:"+@port.to_s
    temphosts=Array.new()
    temphosts.push(prihost)
    
    if (@backup)
      @loadbalance=false
      @distribute=false
    elsif (@loadbalance)    
      @backup=false
      @distribute=false
    elsif (@distribute)
      @backup=false
      @loadbalance=false
    end
      
    if (!@backuphosts.nil?)
      @hosts=temphosts|@backuphosts
    else
      @hosts=Array.new(temphosts)
    end
    
    while @send 
      @current_host, @current_port = @hosts[@host_idx].split(':')
      begin
        if (@msgsendfail && @backup) || (@loadbalance)
          @host_idx = (@host_idx<@hosts.size-1) ? @host_idx + 1 : 0
          if (@msgsendfail)
            @logger.warn("syslog " + @protocol + "Resending Message to", :host => @current_host, :port => @current_port)
          end
          @multiconnect_sockets[@hosts[@host_idx]] ||= connect(@current_host,Integer(@current_port))	
          @multiconnect_sockets[@hosts[@host_idx]].write(syslog_msg + "\n")
          @send=false
          @msgsendfail=false
          if (@backup)
            @host_idx = 0     
            @multiconnect_sockets[@hosts[0]] = nil
          end
          break
        elsif (@distribute)
          @hosts.each do | host |
            begin
              @current_host, @current_port = host.split(':')
              @multiconnect_sockets[host] ||= connect(@current_host,Integer(@current_port))
              @multiconnect_sockets[host].write(syslog_msg + "\n")
              @send=false
              @msgsendfail=false
            rescue => e
              @logger.warn("syslog " + @protocol + " output exception: closing, could not send event to ", :host => @current_host, :port => @current_port, :exception => e, :backtrace => e.backtrace, :event => event)
              @multiconnect_sockets[host].close rescue nil
              @multiconnect_sockets[host] = nil
              next
            end  
          end
        else
          @multiconnect_sockets[@hosts[@host_idx]] ||= connect(@current_host,Integer(@current_port))
          @multiconnect_sockets[@hosts[@host_idx]].write(syslog_msg + "\n")
          @send=false
          @msgsendfail=false
          break
        end
      rescue => e
        # We don't expect udp connections to fail because they are stateless, but ...
        # udp connections may fail/raise an exception if used with localhost/127.0.0.1
        if udp?
          @send = false
          break
        end
        @logger.warn("syslog " + @protocol + " output exception: closing, could not send event to ", :host => @current_host, :port => @current_port, :exception => e, :backtrace => e.backtrace, :event => event)
        @multiconnect_sockets[@hosts[@host_idx]].close rescue nil
        @multiconnect_sockets[@hosts[@host_idx]] = nil
        @msgsendfail=true
	sleep(@reconnect_interval)
      end
    end
  end 
  
  private

  def udp?
    @protocol == "udp"
  end

  def ssl?
    @protocol == "ssl-tcp"
  end

  def connect(chost,cport)
    socket = nil
    if udp?
      socket = UDPSocket.new
      socket.connect(chost,cport)
    else
      socket = TCPSocket.new(chost,cport)
      if ssl?
        socket = OpenSSL::SSL::SSLSocket.new(socket, @ssl_context)
        begin
          socket.connect
        rescue OpenSSL::SSL::SSLError => ssle
          @logger.error("SSL Error", :exception => ssle,
                        :backtrace => ssle.backtrace)
          # NOTE(mrichar1): Hack to prevent hammering peer
          sleep(5)
          raise
        end
      end
    end
    socket
  end

  def setup_ssl
    require "openssl"
    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(@ssl_cert))
    ssl_context.key = OpenSSL::PKey::RSA.new(File.read(@ssl_key),@ssl_key_passphrase)
    if @ssl_verify
      cert_store = OpenSSL::X509::Store.new
      # Load the system default certificate path to the store
      cert_store.set_default_paths
      if File.directory?(@ssl_cacert)
        cert_store.add_path(@ssl_cacert)
      else
        cert_store.add_file(@ssl_cacert)
      end
      ssl_context.cert_store = cert_store
      ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    end
    ssl_context
  end
end
