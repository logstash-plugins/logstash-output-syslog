# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/syslog"
require "logstash/codecs/plain"
require "json"

describe LogStash::Outputs::Syslog do
  FIXTURES_PATH = File.expand_path("../fixtures", File.dirname(__FILE__))

  subject do
    plugin = LogStash::Plugin.lookup("output", "syslog").new(options)
    plugin.register
    plugin
  end

  let(:port) do
    begin
      # Start high to better avoid common services
      port = rand(10000..65535)
      s = TCPServer.new("127.0.0.1", port)
      s.close

      port
    rescue Errno::EADDRINUSE
      retry
    end
  end

  let(:server) { TCPServer.new("127.0.0.1", port) }

  shared_examples "syslog output" do
    it "should write expected format" do
      Thread.start { sleep 0.25; subject.receive event }
      socket = secure_server.accept
      read = socket.sysread(100)
      expect(read.size).to be > 0
      expect(read).to match(output)
    end
  end

  context "connects with TLS" do
    let(:event) { LogStash::Event.new({ "message" => "foo bar", "host" => "baz" }) }
    let(:options) { { "host" => "localhost", "port" => port, "protocol" => "ssl-tcp",
      "ssl_cacert" => File.join(FIXTURES_PATH, "ca.pem"),
      "ssl_cert" => File.join(FIXTURES_PATH, "client.pem"),
      "ssl_key" => File.join(FIXTURES_PATH, "client-key.pem") } }
    # The output details are tested in syslog_spec.rb so simply check for message to be present.
    let(:output) { /foo bar/ }

    let(:secure_server) do
      # Create TLS server with given certificate and private key, and verify client certificate against CA.
      ssl_context = OpenSSL::SSL::SSLContext.new
      ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(server_cert_file))
      ssl_context.key = OpenSSL::PKey::read(File.read(server_pkey_file), nil)
      ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ssl_context.cert_store = OpenSSL::X509::Store.new
      ssl_context.cert_store.add_cert(OpenSSL::X509::Certificate.new(File.read(File.join(FIXTURES_PATH, "ca.pem"))))
      OpenSSL::SSL::SSLServer.new(server, ssl_context)
    end

    after(:each) do
      secure_server.close rescue nil
    end

    context "server with valid certificates" do
      let(:options ) { super().merge("ssl_verify" => true) }
      let(:server_cert_file) { File.join(FIXTURES_PATH, "valid-server.pem") }
      let(:server_pkey_file) { File.join(FIXTURES_PATH, "valid-server-key.pem") }

      it_behaves_like "syslog output"
    end

    context "server with untrusted certificates" do
      let(:server_cert_file) { File.join(FIXTURES_PATH, "untrusted-server.pem") }
      let(:server_pkey_file) { File.join(FIXTURES_PATH, "untrusted-server-key.pem") }

      context "ssl_verify disabled" do
        let(:options ) { super().merge("ssl_verify" => false) }

        it_behaves_like "syslog output"
      end

      context "ssl_verify enabled" do
        let(:options ) { super().merge("ssl_verify" => true) }

        it "should refuse to connect" do
          Thread.start { secure_server.accept rescue nil }
          expect(subject.logger).to receive(:error).with(/SSL Error/i, hash_including(exception: OpenSSL::SSL::SSLError)).once.and_throw :TEST_DONE
          expect { subject.receive event }.to throw_symbol(:TEST_DONE)
        end
      end

    end

    context "server with revoked certificates" do
      let(:options ) { super().merge("ssl_verify" => true, "ssl_crl" => File.join(FIXTURES_PATH, "ca-crl.pem")) }
      let(:server_cert_file) { File.join(FIXTURES_PATH, "revoked-server.pem") }
      let(:server_pkey_file) { File.join(FIXTURES_PATH, "revoked-server-key.pem") }

      it "syslog output refuses to connect" do
        Thread.start { secure_server.accept rescue nil }
        expect(subject.logger).to receive(:error).with(/SSL Error/i, hash_including(exception: OpenSSL::SSL::SSLError)).once.and_throw :TEST_DONE
        expect { subject.receive event }.to throw_symbol(:TEST_DONE)
      end
    end
  end

  context "read PEM" do
    let(:options) { { "host" => "localhost", "port" => port, "protocol" => "ssl-tcp", "ssl_verify" => true } }

    context "RSA certificate and private key" do
      let(:options ) { super().merge(
        "ssl_cert" => File.join(FIXTURES_PATH, "client.pem"),
        "ssl_key" => File.join(FIXTURES_PATH, "client-key.pem"),
        "ssl_cacert" => File.join(FIXTURES_PATH, "ca.pem"),
        "ssl_crl"  => File.join(FIXTURES_PATH, "ca-crl.pem")
      ) }

      it "register succeeds" do
        expect { subject.register }.not_to raise_error
      end
    end

    context "EC certificate and private key" do
      let(:options ) { super().merge(
        "ssl_cert" => File.join(FIXTURES_PATH, "client-ec.pem"),
        "ssl_key" => File.join(FIXTURES_PATH, "client-ec-key.pem"),
        "ssl_cacert" => File.join(FIXTURES_PATH, "ca.pem"),
        "ssl_crl"  => File.join(FIXTURES_PATH, "ca-crl.pem")
      ) }

      it "register succeeds" do
        expect { subject.register }.not_to raise_error
      end
    end

    context "invalid client certificate" do
      let(:options ) { super().merge(
        "ssl_cert" => File.join(FIXTURES_PATH, "invalid.pem"),
        "ssl_key" => File.join(FIXTURES_PATH, "client-key.pem"),
        "ssl_cacert" => File.join(FIXTURES_PATH, "ca.pem"),
        "ssl_crl"  => File.join(FIXTURES_PATH, "ca-crl.pem")
      ) }

      it "register raises error" do
        expect { subject.register }.to raise_error(OpenSSL::X509::CertificateError, /malformed PEM data/)
      end
    end

    context "invalid CRL" do
      let(:options ) { super().merge(
        "ssl_cert" => File.join(FIXTURES_PATH, "client.pem"),
        "ssl_key" => File.join(FIXTURES_PATH, "client-key.pem"),
        "ssl_cacert" => File.join(FIXTURES_PATH, "ca.pem"),
        "ssl_crl"  => File.join(FIXTURES_PATH, "invalid.pem")
      ) }

      it "register raises error" do
        expect { subject.register }.to raise_error(OpenSSL::X509::CRLError, /malformed PEM data/)
      end
    end

  end
end
