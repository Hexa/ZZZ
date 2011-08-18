# -*- coding: utf-8 -*-

require 'rspec'
require 'time'
require 'openssl'
require 'zzz/ca/crl'
require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe ZZZ::CA::CRL do
  context "インスタンスを生成した場合" do
    before do
      module ZZZ; module CA; class Utils; end; end; end

      @crl_pem = <<-CRL
-----BEGIN X509 CRL-----
MIIBZTCBzwIBATANBgkqhkiG9w0BAQUFADBCMQswCQYDVQQDDAJDTjEOMAwGA1UE
CAwFVG9reW8xCjAIBgNVBAcMAUwxCzAJBgNVBAYTAkpQMQowCAYDVQQKDAFvFw0x
MDEwMjcxNDA1MDBaFw0xMDExMDMxNDA1MDBaMCgwEgIBGBcNMTAxMDI3MTQwNTAw
WjASAgEZFw0xMDEwMjcxNDA1MDBaoC8wLTAKBgNVHRQEAwIBEjAfBgNVHSMEGDAW
gBST1ffQ3NubF9S0zbA+Ih128OOt5TANBgkqhkiG9w0BAQUFAAOBgQCiFdMY8KRW
cL070DDfAIHWI/XaJEZ8qNlLfEU5SuQSRdv48PrVL2pXMyxd0nw5LC+BlXaaJ9vI
Uo/n76qbsYDFWsllACWBNLYuz4ZdBQjWRYX3sxanAko2w1F8Ka1GgKvwFI+o68SY
SedKdfhDSfXje1DPji8PMlEX2lMwvnYrmg==
-----END X509 CRL-----
      CRL

      @rsa_private_key = <<-PrivateKey
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQD4GGnFOZay4OlHKRFZUP0o2IbNYFpkkE52iTslwy9HriXLA1rU
vs66qsfMNyd37x+ZORWOlaCZkapwl4hzhbSBD7g2rlsnllmL59MbjsErues0fZkE
P9tUInDZv+8Wjd8dxtor/6404zRyxyNbEodWo+NsEzq+8oLlhK2yBuaF5QIDAQAB
AoGAF1KsNtdIHH7aT09EC0J62iko2wvQ051hUvFptw4XVsS/Vst08YUSiCff6onQ
0wyOyue76BCW7XjtLfKA6GNMaZo/FExZ+9yeL84PkFbG3Dfesnb+AK47zaUkXVBT
fmJu1Jz2Fhze3hPYrOEo2TG2NUIQ1XprexdcBJxZa3MpE40CQQD99ysLlfsuV2hV
ZBeq605qM2lWyJxhXB3Cwc7zVr8yVweOYJe3DUjBTlBDWH3HZtIY71m5OALjgYDu
Grk5Qm5bAkEA+hU04PYczKUBCEJJ+Tnr0vu3eBHc/ljS3BbRwvaNC55l7Oelh4nn
qB8Hzc6sJ/Ujl1+gXWDJUftzx+ULejmQvwJAHut3zypMcYDsz/CmvQV2/5EQ0yML
fwMDEJIeCxxVnOBhqCD0d7HjWL2bIgflEGDhVW3Wo6lBGMfMlbClOmZvHwJBALea
KCddKUmpfreEi3C5cISGn208mCX4Kl7BNiFQB79W/HfQnfuDaJtKpN0ZddUkKYwx
/bdwnn1dAeTpKOMELlsCQQDfh366syj0bWm3hPkVp1m/4S7fn0NKcWbcW4B7iHST
yn4M/nmsCAS2R1vrYOvtMzWWYeL7G3HtfPaCLUpM4/Lx
-----END RSA PRIVATE KEY-----
      PrivateKey

      ZZZ::CA::Utils.should_receive(:new).with(:crl, nil).and_return(OpenSSL::X509::CRL.new)
      @crl = ZZZ::CA::CRL.new
    end

    it "#crl=(crl_pem) 後の #crl は OpenSSL::X509::CRL オブジェクトを返すこと" do
      ZZZ::CA::Utils.should_receive(:x509_object).with(:crl, @crl_pem).and_return(OpenSSL::X509::CRL.new(@crl_pem))
      @crl.crl = @crl_pem
      @crl.crl.class.should == OpenSSL::X509::CRL
    end

    it "#crl=(der) 後の #crl は OpenSSL::X509::CRL オブジェクトを返すこと" do
      der = OpenSSL::X509::CRL.new(@crl_pem).to_der
      ZZZ::CA::Utils.should_receive(:x509_object).with(:crl, der).and_return(OpenSSL::X509::CRL.new(der))
      @crl.crl = der
      @crl.crl.class.should == OpenSSL::X509::CRL
    end


    it "#add_revoked(:serial => 1, :datetime => \"2011/05/12 00:00:00\") は OpenSSL::X509::Revoked オブジェクトを返すこと" do
      @crl.add_revoked(:serial => 1, :datetime => "2011/05/12 00:00:00").class.should == OpenSSL::X509::Revoked
    end

    it "#private_key=(rsa_private_key) は OpenSSL::PKey::RSA オブジェクトを返すこと" do
    end

    it "#last_update='2011/05/10 00:00:00' を指定した後の #last_update は '2010/09/21 00:00:00' の Time オブジェクトを返すこと" do
      time = '2010/09/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      @crl.last_update = time
      @crl.last_update.should == Time.parse(time)
    end

    it "#next_update='2011/05/10 00:00:00' を指定した後の #next_update は '2010/09/21 00:00:00' の Time オブジェクトを返すこと" do
      time = '2010/09/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      @crl.next_update = time
      @crl.next_update.should == Time.parse(time)
    end

    it "#sign(:signer => signer) は ZZZ::CA::CRL オブジェクトを返すこと" do
      signer = double('signer')
      name = OpenSSL::X509::Name.new
      name.add_entry('CN', 'cn')
      signer.should_receive(:subject).and_return(name)
      private_key = OpenSSL::PKey::RSA.new(@rsa_private_key)
      signer.should_receive(:private_key).and_return(private_key)
      time = '2010/09/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      @crl.last_update = time
      time = '2010/10/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      @crl.next_update = time
      subject = [{'CN' => 'CA'}]
      @crl.sign(:signer => signer).class.should == ZZZ::CA::CRL
    end

    it "#sign(:signer => signer, :version => 0) で署名した後の CRL のバージョンは 0 であること" do
      signer = double('signer')
      name = OpenSSL::X509::Name.new
      name.add_entry('CN', 'cn')
      signer.should_receive(:subject).and_return(name)
      private_key = OpenSSL::PKey::RSA.new(@rsa_private_key)
      signer.should_receive(:private_key).and_return(private_key)
      time = '2010/09/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      @crl.last_update= time
      time = '2010/10/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      @crl.next_update = time
      subject = [{'CN' => 'CA'}]
      @crl.sign(:signer => signer, :version => 0)
      @crl.version.should == 0
    end

    it "#revoked(serial, time) は指定した serial の OpenSSL::X509::Revoked オブジェクトを返すこと" do
      2.times do |serial|
        revoked = OpenSSL::X509::Revoked.new
        revoked.serial = serial
        time = Time.now
        revoked.time = time
        ZZZ::CA::Utils.should_receive(:encode_datetime) \
                      .with(time.to_s) \
                      .and_return(time)
        @crl.add_revoked(:serial => serial, :datetime => time.to_s).serial.should == revoked.serial
      end
    end

    after do
      @crl = nil
      @crl_pem = nil
    end
  end
end
