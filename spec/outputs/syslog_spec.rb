# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/syslog"
require "logstash/codecs/plain"

describe LogStash::Outputs::Syslog do

  it "should register without errors" do
    plugin = LogStash::Plugin.lookup("output", "syslog").new({"host" => "foo", "port" => "123", "facility" => "kernel", "severity" => "emergency"})
    expect { plugin.register }.to_not raise_error
  end

  subject do
    plugin = LogStash::Plugin.lookup("output", "syslog").new(options)
    plugin.register
    plugin
  end

  let(:socket) { double("fake socket") }
  let(:event) { LogStash::Event.new({"message" => "bar", "host" => "baz"}) }

  shared_examples "syslog output" do
    it "should write expected format" do
      expect(subject).to receive(:connect).and_return(socket)
      expect(socket).to receive(:write).with(output)
      subject.receive(event)
    end
  end

  context "rfc 3164 and udp by default" do
    let(:options) { {"host" => "foo", "port" => "123", "facility" => "kernel", "severity" => "emergency"} }
    let(:output) { /^<0>.+baz LOGSTASH\[-\]: bar\n/m }

    it_behaves_like "syslog output"
  end

  context "rfc 5424 and tcp" do
    let(:options) { {"rfc" => "rfc5424", "protocol" => "tcp", "host" => "foo", "port" => "123", "facility" => "kernel", "severity" => "emergency"} }
    let(:output) { /^<0>1 .+baz LOGSTASH - - - bar\n/m }

    it_behaves_like "syslog output"
  end

  context "calculate priority" do
    let(:options) { {"host" => "foo", "port" => "123", "facility" => "mail", "severity" => "critical"} }
    let(:output) { /^<18>.+baz LOGSTASH\[-\]: bar\n/m }

    it_behaves_like "syslog output"
  end

  context "use plain codec with format set" do
    let(:plain) { LogStash::Codecs::Plain.new({"format" => "%{host} %{message}"}) }
    let(:options) { {"host" => "foo", "port" => "123", "facility" => "kernel", "severity" => "emergency", "codec" => plain} }
    let(:output) { /^<0>.+baz LOGSTASH\[-\]: baz bar\n/m }

    it_behaves_like "syslog output"
  end

  context "use codec json" do
    let(:options) { {"host" => "foo", "port" => "123", "facility" => "kernel", "severity" => "emergency", "codec" => "json" } }
    let(:output) { /^<0>.+baz LOGSTASH\[-\]: {\"message\":\"bar\",\"host\":\"baz\",\"@version\":\"1\",\"@timestamp\":\"[0-9TZ:.+-]+\"}\n/m }

    it_behaves_like "syslog output"
  end
end
