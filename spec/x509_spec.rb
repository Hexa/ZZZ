# -*- coding: utf-8 -*-

require 'rspec'
require 'zzz/ca/x509'

describe ZZZ::CA::X509 do
  context "" do
    before do
      @x509 = ZZZ::CA::X509.new(:certificate)
      @oid = 'CN'

      @ca_cn = 'CN'
      ca_name = OpenSSL::X509::Name.new
      ca_name.add_entry(@oid, @ca_cn)
      @ca_name = ca_name

      @server_cn = 'example.com'
      server_name = OpenSSL::X509::Name.new
      server_name.add_entry(@oid, @server_cn)
      @server_name = server_name
    end

    it { ->{ @x509.sign(:invalid, '') }.should raise_error ZZZ::CA::Error }

    it "#subject は #add_subject(oid, value) で追加した oid, value の OpenSSL::X509::Name オブジェクトを返すこと" do
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with([{@oid => @ca_cn}])
                    .and_return(@ca_name)
      @x509.add_subject(@oid, @ca_cn)
      @x509.subject.should be_an_instance_of OpenSSL::X509::Name
      @x509.subject.to_s.should be_eql @ca_name.to_s
    end

    after do
      @x509 = nil
      @ca_cn = nil
      @ca_name = nil
      @server_cn = nil
      @server_name = nil
    end
  end
end
