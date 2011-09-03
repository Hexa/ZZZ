# -*- coding: utf-8 -*-

require 'rspec'
require 'time'
require 'openssl'
require 'zzz/ca/certificate'
require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe ZZZ::CA::Certificate do
  context "インスタンスを生成する場合" do
    before do
      @certificate_pem = <<-Certificate
-----BEGIN CERTIFICATE-----
MIICdjCCAd+gAwIBAgIBFzANBgkqhkiG9w0BAQUFADBCMQswCQYDVQQDDAJDTjEO
MAwGA1UECAwFVG9reW8xCjAIBgNVBAcMAUwxCzAJBgNVBAYTAkpQMQowCAYDVQQK
DAFvMB4XDTEwMTAyNzE0MDQyMloXDTEwMTEyNjE0MDQyMlowPzELMAkGA1UEAwwC
Q04xCzAJBgNVBAgMAnN0MQowCAYDVQQHDAFsMQswCQYDVQQGEwJKUDEKMAgGA1UE
CgwBbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzdZC7O0uGvWEhfPp+nC6
4BoU6hRjHMXF61jPNoHugLeNPotp68qcv0Oaz2SSWTBTDBk4MeiD7r+i+XrtyDwp
lu6SKLPi4haIQUfRAkLjn2Jq8L4x5kwcMeGY/hdW/gA4K5vqQremCljfuKpokKFA
HIaYR+sYccovK2PMUe+mKkkCAwEAAaN/MH0wDwYDVR0TBAgwBgEB/wIBADALBgNV
HQ8EBAMCAYYwHQYDVR0OBBYEFAdQS7AkuJSd7tMc17u3oYlVvDjEMB8GA1UdIwQY
MBaAFJPV99Dc25sX1LTNsD4iHXbw463lMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjANBgkqhkiG9w0BAQUFAAOBgQCeS85lYMlcnlRoycksDBIP8RrMW0BM
utv0yYH9yiMjN3lVG6wKLsLkJHP7HuY5TpYwV/6OzHZvp5NEJpSE9xc5iImY86JC
JO2h5womlEjvvb3FWyVGGYAue+hPGDSZ//qXgahOOSscl9+HgwIZp0GA+KIgOPim
UPt704SNSQNfqQ==
-----END CERTIFICATE-----
      Certificate
      module ZZZ; module CA; class Utils; end; end; end
    end

    it '::new はZZZ::CA::Certificate インスタンスを生成すること' do
      ZZZ::CA::Utils.should_receive(:new)
                    .and_return(OpenSSL::X509::Certificate.new)
      ZZZ::CA::Certificate.new.should be_an_instance_of ZZZ::CA::Certificate
    end

    it '::new(pem) はZZZ::CA::Certificate インスタンスを生成すること' do
      ZZZ::CA::Utils.should_receive(:new)
                    .with(:certificate, @certificate_pem)
                    .and_return(OpenSSL::X509::Certificate.new(@certificate_pem))
      ZZZ::CA::Certificate.new(@certificate_pem).should be_an_instance_of ZZZ::CA::Certificate
    end

    after do
      @certificate_pem = nil
    end
  end

  context "インスタンスを生成した場合" do
    before do
      @rsa_private_key_pem = <<-PrivateKey
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
      @rsa_private_key = OpenSSL::PKey::RSA.new(@rsa_private_key_pem)

      @dsa_private_key_pem = <<-PrivateKey
-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCiiJlyko3kqUBdT8vFIIpTbfPfkSmMePqJ0heLYtVmGNPTWlSm
SeY7prl2+/ccl8uXZOn0jBwGVKoOSbB/tFatjcWXTYEytgdI6fAtTEbfL0d4Mo06
DUZtNB0j/5jZRAACOLvyoZWvfvFhzE8hDjlFHxL4Q4Lp2b3K7JHM3yMwnQIVAJlL
p5l7PNmKPc/Bn0CvGhvf/oHFAoGAeevy0gkE8MSSK1Pf7aPV6B3kzbGCSdbkFPUL
kELgqLSnpB7B2ao1O7tGDu0Yu7HSo/+/p73g3Ds6Ig+XJLgCGvYSnomBHStmebsR
We6gjaqinl0kjjZ6zUqeiMdXQ/jdHQi6nmTjPYzGXmveEOwqVytiN6PioHYmBexJ
7Fo3BGgCgYA/tPO6j8013kLwAp+/+zpHm1haZB5AGvo16sz9USG0w8THFvQ3DCYn
9ZIxzMua2mmj3SdNBsVa0OEt0IvbOdYi6Okwyu+JJSl1K20GC9Sma8ioBQQbtbC/
B1979IiYO3XGSpf48FGrzSAwTlYYs7OUNgDDO9qx2gxSIuM61+r8ywIVAJFvj/9B
/9/fLjdghw+EwM0BSzA8
-----END DSA PRIVATE KEY-----
      PrivateKey
      @dsa_private_key = OpenSSL::PKey::DSA.new(@dsa_private_key_pem)

      ZZZ::CA::Utils.should_receive(:new)
                    .at_least(:once)
                    .and_return(OpenSSL::X509::Certificate.new)
      @certificate = ZZZ::CA::Certificate.new
    end

    it "#gen_private_key は RAS Private Key を返すこと" do
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with({})
                    .and_return(@rsa_private_key)
      @certificate.gen_private_key.to_s.should =~ /^-----BEGIN RSA PRIVATE KEY-----.+-----END RSA PRIVATE KEY-----$/m
    end

    it "#gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA) は DSA Private Key を返すこと" do
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      @certificate.gen_private_key(params).to_s.should =~ /^-----BEGIN DSA PRIVATE KEY-----.+-----END DSA PRIVATE KEY-----$/m
    end

    it "#private_key=rsa_private_key （PEM）を指定した後の #private_key は OpenSSL::PKey::RSA オブジェクトを返すこと" do
      ZZZ::CA::Utils.should_receive(:get_pkey_object)
                    .with(@rsa_private_key_pem)
                    .and_return(@rsa_private_key)
      @certificate.private_key = @rsa_private_key_pem
      @certificate.private_key.class.should == OpenSSL::PKey::RSA
    end

    it "#private_key=rsa_private_key （OpenSSL::PKey::RSA オブジェクト）を指定した後の #private_key は OpenSSL::PKey::RSA オブジェクトを返すこと" do
      @certificate.private_key = @rsa_private_key
      @certificate.private_key.class.should == OpenSSL::PKey::RSA
    end

    it "#private_key=nil の場合は例外を発生させること" do
      lambda { @certificate.private_key = nil }.should raise_error ZZZ::CA::Error
    end

    it "#private_key=rsa_private_key （不正な PEM）を指定した場合は例外を発生させること" do
      ZZZ::CA::Utils.should_receive(:get_pkey_object)
                    .and_raise(ZZZ::CA::Error.new)
      lambda { @certificate.private_key = 'invalid' }.should raise_error ZZZ::CA::Error
    end

    it "#encrypted_private_key は暗号化した Private Key を返すこと" do
      rsa_private_key = <<-PrivateKey
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
      ZZZ::CA::Utils.should_receive(:get_pkey_object)
                    .with(rsa_private_key)
                    .and_return(OpenSSL::PKey::RSA.new(rsa_private_key))
      @certificate.private_key = rsa_private_key
      ZZZ::CA::Utils.should_receive(:cipher)
                    .with('AES-256-CBC')
                    .and_return(OpenSSL::Cipher::Cipher.new('AES-256-CBC'))
      @certificate.encrypted_private_key(:algorithm => 'AES-256-CBC', :passphrase => 'pass').should =~ /^-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,.+-----END RSA PRIVATE KEY-----$/m
    end

    it "#not_before='2011/05/10 00:00:00' を指定した後の #not_before は '2010/09/21 00:00:00' の Time オブジェクトを返すこと" do
      time = '2010/09/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(time)
                    .and_return(Time.parse(time))
      @certificate.not_before = time
      @certificate.not_before.should == Time.parse(time)
    end

    it "#not_after='2011/05/10 00:00:00' を指定した後の #not_after は '2010/09/21 00:00:00' の Time オブジェクトを返すこと" do
      time = '2010/09/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(time)
                    .and_return(Time.parse(time))
      @certificate.not_after = time
      @certificate.not_after.should == Time.parse(time)
    end

    it "#sign は ZZZ::CA::Certificate オブジェクトを返すこと" do
      time = '2010/09/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(time)
                    .and_return(Time.parse(time))
      @certificate.not_before = '2010/09/21 00:00:00'
      time = '2010/10/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(time) \
                    .and_return(Time.parse(time))
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      name = OpenSSL::X509::Name.new
      subject.each do |e|
        e.each_pair do |key, value|
          name.add_entry(key, value)
        end
      end
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(subject)
                    .and_return(name)
      @certificate.subject = subject
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      @certificate.gen_private_key(params)
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .and_return(name)
      @certificate.sign(:serial => 1).class.should == ZZZ::CA::Certificate
    end

    it "#sign(:version => 1) で署名した後の証明書のバージョンは 1 であること" do
      time = '2010/09/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      @certificate.not_before = time
      time = '2010/10/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      @certificate.not_after = time
      subject = [{'CN' => 'CA'}]
      name = OpenSSL::X509::Name.new
      subject.each do |e|
        e.each_pair do |key, value|
          name.add_entry(key, value)
        end
      end
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(subject)
                    .and_return(name)
      @certificate.subject = subject
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      @certificate.gen_private_key(params)
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .and_return(name)
      @certificate.sign(:serial => 1, :version => 1)
      @certificate.version.should == 1
    end

    it "#sign(:signer => ca) で CA が署名した後の証明書の発行者は署名した CA であること" do
      ca = ZZZ::CA::Certificate.new
      time = '2010/09/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      ca.not_before = '2010/09/21 00:00:00'
      time = '2010/10/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      ca.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      name = OpenSSL::X509::Name.new
      subject.each do |e|
        e.each_pair do |key, value|
          name.add_entry(key, value)
        end
      end
      ca.subject = subject
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :RSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey) \
                    .with(params)
                    .and_return(@dsa_private_key)
      ca.gen_private_key(params)
      ZZZ::CA::Utils.should_receive(:encode_subject) \
                    .at_least(:once) \
                    .and_return(name)
      ca.sign(:serial => 1, :version => 1)
      time = '2010/09/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      @certificate.not_before = '2010/09/21 00:00:00'
      time = '2010/10/21 00:00:00'
      ZZZ::CA::Utils.should_receive(:encode_datetime) \
                    .with(time) \
                    .and_return(Time.parse(time))
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'Server'}]
      name = OpenSSL::X509::Name.new
      subject.each do |e|
        e.each_pair do |key, value|
          name.add_entry(key, value)
        end
      end
      @certificate.subject = subject
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      @certificate.gen_private_key(params)
      issuer = [{'CN' => 'CA'}]
      name = OpenSSL::X509::Name.new
      issuer.each do |e|
        e.each_pair do |key, value|
          name.add_entry(key, value)
        end
      end
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .and_return(name)
      @certificate.sign(:serial => 2, :signer => ca)
      p @certificate.issuer
      @certificate.issuer.to_s.should == (OpenSSL::X509::Name.new).add_entry('CN', 'CA').to_s
    end

    it "#signature_algorithm は #signature_algorithm= で指定したアルゴリズムを返すこと" do
      @certificate.signature_algorithm = 'MD5'
      @certificate.signature_algorithm.should == 'MD5'
      @certificate.signature_algorithm.should_not == 'SHA1'
    end

    it "#signature_algorithm は署名に使用したアルゴリズムを返すこと" do
      @certificate.not_before = '2010/09/21 00:00:00'
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      @certificate.subject = subject
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      @certificate.sign(:serial => 1)
      @certificate.signature_algorithm.should == 'dsaWithSHA1'
    end

    it "#add_extension('oid', ['value1', 'value2'], critical = true}) を指定して、署名した後の証明書は指定した extension を含んでいること" do
      request =<<-PEM
-----BEGIN CERTIFICATE REQUEST-----
MIIBaTCB0wIAMCsxEDAOBgNVBAMMB2V4YW1wbGUxCjAIBgNVBAoMAU8xCzAJBgNV
BAYTAkpQMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYRAol+Ha48uTbOZfK
qTOjXuZJvS2hjVsr/ES6GP2+a2VMx9bRmSCQ6orlNF71e7p33zoB7Z05nbRFBwDu
hHz1kc5J/aqoRzDVqIpQgdSnFtfg9VmEILTWvu170QXVoE9KZOOvqu63NiHSFlJg
kwVCODKlf837nkALbnOOqGkTpwIDAQABoAAwDQYJKoZIhvcNAQEFBQADgYEAQO7A
ZMouRrcCZBKP10EKNfhOX9qo3HOfm72oK3kQVlXmIrlQKZWuUmDIHNcWbMcrxnQ/
cttiBtpYtVg2eWJu91/Bmpj8aXRNE+KQ1Mj+9exe6ykqYG+1/sF46OdYmCEwQIxV
FPiXrLzArhOXX1ubOCbSBUCOIHMNovWLFWGZ6qA=
-----END CERTIFICATE REQUEST-----
      PEM

      @certificate.not_before = '2010/09/21 00:00:00'
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      @certificate.subject = subject
      @certificate.subject_request = request
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      @certificate.add_extension('basicConstraints', ['CA:TRUE', 'pathlen:1'], true)
      @certificate.add_extension('keyUsage', ['keyCertSign', 'cRLSign'])
      @certificate.add_extension('subjectKeyIdentifier', ['hash'])
      @certificate.sign(:serial => 1)

      extensions = []
      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extensions << extension_factory.create_ext('basicConstraints', 'CA:TRUE, pathlen:1', true)
      extensions << extension_factory.create_ext('keyUsage', 'Certificate Sign, CRL Sign', false)
      extension_factory.subject_request = OpenSSL::X509::Request.new(request)
      extensions << extension_factory.create_ext('subjectKeyIdentifier', 'hash', false)
      @certificate.extensions.to_s.should == extensions.to_s
    end

    it "#extension = extensions を指定して、署名した後の証明書は指定した extension を含んでいること" do
      @certificate.not_before = '2010/09/21 00:00:00'
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      @certificate.subject = subject
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      extensions = {}
      extensions['basicConstraints'] = {:values => ['CA:TRUE', 'pathlen:1'], :critical => true}
      extensions['keyUsage'] = {:values => ['keyCertSign', 'cRLSign']}
      @certificate.extensions = extensions
      @certificate.sign(:serial => 1)

      extensions = []
      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extensions << extension_factory.create_ext('basicConstraints', 'CA:TRUE, pathlen:1', true)
      extensions << extension_factory.create_ext('keyUsage', 'Certificate Sign, CRL Sign', false)
      @certificate.extensions.to_s.should == extensions.to_s
    end

    it do
      certificate_pem = <<-Certificate
-----BEGIN CERTIFICATE-----
MIICdjCCAd+gAwIBAgIBFzANBgkqhkiG9w0BAQUFADBCMQswCQYDVQQDDAJDTjEO
MAwGA1UECAwFVG9reW8xCjAIBgNVBAcMAUwxCzAJBgNVBAYTAkpQMQowCAYDVQQK
DAFvMB4XDTEwMTAyNzE0MDQyMloXDTEwMTEyNjE0MDQyMlowPzELMAkGA1UEAwwC
Q04xCzAJBgNVBAgMAnN0MQowCAYDVQQHDAFsMQswCQYDVQQGEwJKUDEKMAgGA1UE
CgwBbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzdZC7O0uGvWEhfPp+nC6
4BoU6hRjHMXF61jPNoHugLeNPotp68qcv0Oaz2SSWTBTDBk4MeiD7r+i+XrtyDwp
lu6SKLPi4haIQUfRAkLjn2Jq8L4x5kwcMeGY/hdW/gA4K5vqQremCljfuKpokKFA
HIaYR+sYccovK2PMUe+mKkkCAwEAAaN/MH0wDwYDVR0TBAgwBgEB/wIBADALBgNV
HQ8EBAMCAYYwHQYDVR0OBBYEFAdQS7AkuJSd7tMc17u3oYlVvDjEMB8GA1UdIwQY
MBaAFJPV99Dc25sX1LTNsD4iHXbw463lMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjANBgkqhkiG9w0BAQUFAAOBgQCeS85lYMlcnlRoycksDBIP8RrMW0BM
utv0yYH9yiMjN3lVG6wKLsLkJHP7HuY5TpYwV/6OzHZvp5NEJpSE9xc5iImY86JC
JO2h5womlEjvvb3FWyVGGYAue+hPGDSZ//qXgahOOSscl9+HgwIZp0GA+KIgOPim
UPt704SNSQNfqQ==
-----END CERTIFICATE-----
      Certificate

      @certificate.certificate = certificate_pem
      @certificate.verify(@certificate.public_key).should == false
    end

    it '#certificate = der は DER 形式の証明書を読み込めること' do
      certificate_pem = <<-Certificate
-----BEGIN CERTIFICATE-----
MIICdjCCAd+gAwIBAgIBFzANBgkqhkiG9w0BAQUFADBCMQswCQYDVQQDDAJDTjEO
MAwGA1UECAwFVG9reW8xCjAIBgNVBAcMAUwxCzAJBgNVBAYTAkpQMQowCAYDVQQK
DAFvMB4XDTEwMTAyNzE0MDQyMloXDTEwMTEyNjE0MDQyMlowPzELMAkGA1UEAwwC
Q04xCzAJBgNVBAgMAnN0MQowCAYDVQQHDAFsMQswCQYDVQQGEwJKUDEKMAgGA1UE
CgwBbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzdZC7O0uGvWEhfPp+nC6
4BoU6hRjHMXF61jPNoHugLeNPotp68qcv0Oaz2SSWTBTDBk4MeiD7r+i+XrtyDwp
lu6SKLPi4haIQUfRAkLjn2Jq8L4x5kwcMeGY/hdW/gA4K5vqQremCljfuKpokKFA
HIaYR+sYccovK2PMUe+mKkkCAwEAAaN/MH0wDwYDVR0TBAgwBgEB/wIBADALBgNV
HQ8EBAMCAYYwHQYDVR0OBBYEFAdQS7AkuJSd7tMc17u3oYlVvDjEMB8GA1UdIwQY
MBaAFJPV99Dc25sX1LTNsD4iHXbw463lMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjANBgkqhkiG9w0BAQUFAAOBgQCeS85lYMlcnlRoycksDBIP8RrMW0BM
utv0yYH9yiMjN3lVG6wKLsLkJHP7HuY5TpYwV/6OzHZvp5NEJpSE9xc5iImY86JC
JO2h5womlEjvvb3FWyVGGYAue+hPGDSZ//qXgahOOSscl9+HgwIZp0GA+KIgOPim
UPt704SNSQNfqQ==
-----END CERTIFICATE-----
      Certificate

      der = OpenSSL::X509::Certificate.new(certificate_pem).to_der
      @certificate.certificate = der
      @certificate.certificate.should be_an_instance_of OpenSSL::X509::Certificate
    end

    it '#certificate = crl_der は例外を発生させること' do
      crl_pem = <<-CRL
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

      der = OpenSSL::X509::CRL.new(crl_pem).to_der
      lambda { @certificate.certificate = der }.should raise_error( OpenSSL::X509::CertificateError )
    end

    it '#issuer_certificate は #issuer_certificate = pem で指定した PEM 形式の証明書を返すこと' do
      certificate_pem = <<-Certificate
-----BEGIN CERTIFICATE-----
MIICdjCCAd+gAwIBAgIBFzANBgkqhkiG9w0BAQUFADBCMQswCQYDVQQDDAJDTjEO
MAwGA1UECAwFVG9reW8xCjAIBgNVBAcMAUwxCzAJBgNVBAYTAkpQMQowCAYDVQQK
DAFvMB4XDTEwMTAyNzE0MDQyMloXDTEwMTEyNjE0MDQyMlowPzELMAkGA1UEAwwC
Q04xCzAJBgNVBAgMAnN0MQowCAYDVQQHDAFsMQswCQYDVQQGEwJKUDEKMAgGA1UE
CgwBbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzdZC7O0uGvWEhfPp+nC6
4BoU6hRjHMXF61jPNoHugLeNPotp68qcv0Oaz2SSWTBTDBk4MeiD7r+i+XrtyDwp
lu6SKLPi4haIQUfRAkLjn2Jq8L4x5kwcMeGY/hdW/gA4K5vqQremCljfuKpokKFA
HIaYR+sYccovK2PMUe+mKkkCAwEAAaN/MH0wDwYDVR0TBAgwBgEB/wIBADALBgNV
HQ8EBAMCAYYwHQYDVR0OBBYEFAdQS7AkuJSd7tMc17u3oYlVvDjEMB8GA1UdIwQY
MBaAFJPV99Dc25sX1LTNsD4iHXbw463lMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjANBgkqhkiG9w0BAQUFAAOBgQCeS85lYMlcnlRoycksDBIP8RrMW0BM
utv0yYH9yiMjN3lVG6wKLsLkJHP7HuY5TpYwV/6OzHZvp5NEJpSE9xc5iImY86JC
JO2h5womlEjvvb3FWyVGGYAue+hPGDSZ//qXgahOOSscl9+HgwIZp0GA+KIgOPim
UPt704SNSQNfqQ==
-----END CERTIFICATE-----
      Certificate

      @certificate.issuer_certificate = certificate_pem
      @certificate.issuer_certificate.should be_an_instance_of OpenSSL::X509::Certificate
      @certificate.issuer_certificate.to_pem.should == certificate_pem
    end

    it '#subject_request は #subject_request = pem で指定した PEM 形式の CSR を返すこと' do
      request =<<-PEM
-----BEGIN CERTIFICATE REQUEST-----
MIIBaTCB0wIAMCsxEDAOBgNVBAMMB2V4YW1wbGUxCjAIBgNVBAoMAU8xCzAJBgNV
BAYTAkpQMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYRAol+Ha48uTbOZfK
qTOjXuZJvS2hjVsr/ES6GP2+a2VMx9bRmSCQ6orlNF71e7p33zoB7Z05nbRFBwDu
hHz1kc5J/aqoRzDVqIpQgdSnFtfg9VmEILTWvu170QXVoE9KZOOvqu63NiHSFlJg
kwVCODKlf837nkALbnOOqGkTpwIDAQABoAAwDQYJKoZIhvcNAQEFBQADgYEAQO7A
ZMouRrcCZBKP10EKNfhOX9qo3HOfm72oK3kQVlXmIrlQKZWuUmDIHNcWbMcrxnQ/
cttiBtpYtVg2eWJu91/Bmpj8aXRNE+KQ1Mj+9exe6ykqYG+1/sF46OdYmCEwQIxV
FPiXrLzArhOXX1ubOCbSBUCOIHMNovWLFWGZ6qA=
-----END CERTIFICATE REQUEST-----
      PEM

      @certificate.subject_request = request
      @certificate.subject_request.should be_an_instance_of OpenSSL::X509::Request
      @certificate.subject_request.to_pem.should == request
    end

    after do
      @certificate = nil
    end
  end
end
