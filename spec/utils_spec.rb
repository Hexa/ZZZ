# -*- coding: utf-8 -*-

require 'rspec'
require 'zzz/ca/utils'

describe ZZZ::CA::Utils do
  context "OpenSSL インスタンスを生成する場合" do
    it "::new(:certificate) は OpenSSL::X509::Certificate オブジェクトを返すこと" do
      ZZZ::CA::Utils::new(:certificate).should be_an_instance_of OpenSSL::X509::Certificate
    end

    it "::new(:request) は OpenSSL::X509::Request オブジェクトを返すこと" do
      ZZZ::CA::Utils::new(:request).should be_an_instance_of OpenSSL::X509::Request
    end

    it "::new(:crl) は OpenSSL::X509::CRL オブジェクトを返すこと" do
      ZZZ::CA::Utils::new(:crl).should be_an_instance_of OpenSSL::X509::CRL
    end

    it "::new(:unexpected_symbol) は例外を発生させること" do
      -> { ZZZ::CA::Utils::new(:unexpected_symbol) }.should raise_error( ZZZ::CA::Error )
    end
  end

  context "時間をエンコードする場合" do
    it "::encode_datetime(\"2011/05/10 00:00:00\") は 2011/05/10 00:00:00 の Time オブジェクトを返すこと" do
      datetime = "2011/05/10 00:00:00"
      ZZZ::CA::Utils::encode_datetime(datetime).should == Time.parse(datetime)
    end
  end

  context "共通鍵暗号を使用する場合" do
    it "::cipher(\"AES256\") は OpenSSL::Cipher::Cipher オブジェクトを返すこと" do
      ZZZ::CA::Utils::cipher("AES256").should be_an_instance_of OpenSSL::Cipher::Cipher
    end
  end

  context "秘密鍵を生成する場合" do
    it "::gen_pkey は DEFAULT の鍵長，Exponent，公開鍵のアルゴリズムの公開鍵を生成すること" do
      public_key = ZZZ::CA::Utils::gen_pkey({})
      public_key.n.to_i.to_s(2).length.should == 1024
      public_key.e.should == 65567
      public_key.should be_an_instance_of OpenSSL::PKey::RSA
    end

    it "::gen_pkey(:key_size => 2048, :public_exponent => 3, :public_key_algorithm => :DSA) は指定した鍵長，Exponent，公開鍵のアルゴリズムの公開鍵を生成すること" do
      public_key = ZZZ::CA::Utils::gen_pkey(:key_size => 2048, :public_key_algorithm => :DSA)
      public_key.should be_an_instance_of OpenSSL::PKey::DSA
    end
    it "::gen_pkey(:public_key_algorithm => :nil は例外を発生すること" do
      -> { ZZZ::CA::Utils::gen_pkey(:public_key_algorithm => :nil) }.should raise_error( ZZZ::CA::Error )
    end
  end

  context "秘密鍵を読み込む場合" do
    it "::pkey_object(rsa_private_key) は OpenSSL::PKey::RSA オブジェクトを返すこと" do
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
      ZZZ::CA::Utils::pkey_object(rsa_private_key).should be_an_instance_of OpenSSL::PKey::RSA
    end

    it "::pkey_object(dsa_private_key) は OpenSSL::PKey::DSA オブジェクトを返すこと" do
     dsa_private_key_pem = <<-PrivateKey
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
      ZZZ::CA::Utils::pkey_object(dsa_private_key_pem).should be_an_instance_of OpenSSL::PKey::DSA
    end

    it "::pkey_object(private_key) の private_key が不正な書式の場合は例外を発生させること" do
      private_key = <<-PrivateKey
-----BEGIN SSA PRIVATE KEY-----
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
-----END SSA PRIVATE KEY-----
      PrivateKey
      -> { ZZZ::CA::Utils::pkey_object(private_key) }.should raise_error( ZZZ::CA::Error )
    end
  end

  context "PEM を読み込む場合" do
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

      @request_pem =<<-PEM
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

      @crl_pem = <<-PEM
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
      PEM
    end

    it "::x509_object(:certificate, certificate_pem) は OpenSSL::X509::Certificate オブジェクトを返すこと" do
      ZZZ::CA::Utils::x509_object(:certificate, @certificate_pem).should be_an_instance_of OpenSSL::X509::Certificate
    end

    it "::x509_object(:request, request_pem) は OpenSSL::X509::Request オブジェクトを返すこと" do
      ZZZ::CA::Utils::x509_object(:request, @request_pem).should be_an_instance_of OpenSSL::X509::Request
    end

    it "::x509_object(:crl, crl_pem) は OpenSSL::X509::CRL オブジェクトを返すこと" do
      ZZZ::CA::Utils::x509_object(:crl, @crl_pem).should be_an_instance_of OpenSSL::X509::CRL
    end

    it "::x509_object(:certificate, pem) の pem が不正な書式の場合は例外を発生させること" do
      pem = <<-Certificate
------BEGIN CERTIFICATE-----
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
      -> { ZZZ::CA::Utils::x509_object(:certificate, pem) }.should raise_error( OpenSSL::X509::CertificateError )
    end

    it "::x509_object(:csr, pem) の場合は例外を発生させること" do
      -> { ZZZ::CA::Utils::x509_object(:csr, @pem) }.should raise_error( ZZZ::CA::Error )
    end
  end

  context "Extension をエンコードする場合" do
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
      @extensions = {
        'authorityKeyIdentifier' => {
          :values => ['keyid:true'], :critical => true}}
      @params = {}
      @params[:certificates] = {:issuer_certificate => OpenSSL::X509::Certificate.new(@certificate_pem)}
    end

    it "::excode_extensions(extensions, params) は配列で指定された extensions の Extension を OpenSSL::X509::Extension オブジェクトの配列を返すこと" do
      ZZZ::CA::Utils.encode_extensions(@extensions, @params).should be_an_instance_of Array
      ZZZ::CA::Utils.encode_extensions(@extensions, @params)[0].should be_an_instance_of OpenSSL::X509::Extension
    end

    after do
      @certificate_pem = nil
      @extensions = nil
      @params = nil
    end
  end

  context "Subject をエンコードする場合" do
    it "::encode_subject([{'CN' => 'example.com'}]) は OpenSSL::X509::Name オブジェクトを返すこと" do
      ZZZ::CA::Utils.encode_subject([{'CN' => 'example.com'}]).should be_an_instance_of OpenSSL::X509::Name
    end
  end

  context "ASN.1 であることを確認する場合" do
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
    end

    it "::verify_asn1(der) は true を返すこと" do
      certificate = OpenSSL::X509::Certificate.new(@certificate_pem)
      ZZZ::CA::Utils.verify_asn1(certificate.to_der).should be_true
    end

    it "::verify_asn1(pem) は false を返すこと" do
      ZZZ::CA::Utils.verify_asn1(@certificate_pem).should be_false
    end
  end
end
