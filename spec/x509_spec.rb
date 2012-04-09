# -*- coding: utf-8 -*-

require 'rspec'
require 'zzz/ca/x509'

describe ZZZ::CA::X509 do
  context "" do
    before do
      @x509 = ZZZ::CA::X509.new(:certificate)
      l = ->(subjects) do
        name = OpenSSL::X509::Name.new
        subjects.each {|e| e.each_pair {|key, value| name.add_entry(key, value) }}
        name
      end

      e = (0x21..0x7e).to_a.map {|e| e.chr }
      cn = (1..rand(100)).map { e[rand(e.length)] }.join('')
      @ca_name = l.call(@ca_subject = [{'CN' => cn}])
      cn = (1..rand(100)).map { e[rand(e.length)] }.join('')
      @server_name = l.call(@server_subject = [{'CN' => cn}])
    end

    it { ->{ @x509.sign(:invalid, '') }.should raise_error ZZZ::CA::Error }

    it do
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@ca_subject)
                    .and_return(@ca_name)
      @ca_subject.each do |e|
        e.each_pair do |oid, value|
          @x509.add_subject(oid, value)
        end
      end
      @x509.subject.to_s.should == @ca_name.to_s
    end

    after do
      @x509 = nil
      @ca_name = nil
      @ca_subject = nil
      @server_name = nil
      @server_subject = nil
    end
  end
end
