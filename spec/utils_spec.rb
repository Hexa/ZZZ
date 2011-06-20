# -*- coding: utf-8 -*-

require 'rspec'
require 'time'
require 'openssl'
require 'zzz/ca/utils'
require 'zzz/ca/error'

describe ZZZ::CA::Utils do
  context "OpenSSL インスタンスを生成する場合" do
    it "::new(:certificate) は OpenSSL::X509::Certificate オブジェクトを返すこと" do
      ZZZ::CA::Utils::new(:certificate).class.should == OpenSSL::X509::Certificate
    end

    it "::new(:request) は OpenSSL::X509::Request オブジェクトを返すこと" do
      ZZZ::CA::Utils::new(:request).class.should == OpenSSL::X509::Request
    end

    it "::new(:crl) は OpenSSL::X509::CRL オブジェクトを返すこと" do
      ZZZ::CA::Utils::new(:crl).class.should == OpenSSL::X509::CRL
    end

    it "::new(:unexpected_symbol) は例外を発生させること" do
      lambda{ ZZZ::CA::Utils::new(:unexpected_symbol) }.should raise_error( ZZZ::CA::Error )
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
      ZZZ::CA::Utils::cipher("AES256").class.should == OpenSSL::Cipher::Cipher
    end
  end

  context "秘密鍵を読み込む場合" do
    it "::get_pkey_object(rsa_private_key) は OpenSSL::PKey::RSA オブジェクトを返すこと" do
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
      ZZZ::CA::Utils::get_pkey_object(rsa_private_key).class.should == OpenSSL::PKey::RSA
    end

    it "::get_pkey_object(private_key) の private_key が不正な書式の場合は例外を発生させること" do
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
      lambda{ ZZZ::CA::Utils::get_pkey_object(private_key) }.should raise_error( ZZZ::CA::Error )
    end
  end

  context "PEM を読み込む場合" do
    it "::gen_x509_object(certificate_pem) は OpenSSL::X509::Certificate オブジェクトを返すこと" do
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
      ZZZ::CA::Utils::gen_x509_object(certificate_pem).class.should == OpenSSL::X509::Certificate
    end

    it "::gen_x509_object(pem) の pem が不正な書式の場合は例外を発生させること" do
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
      lambda{ ZZZ::CA::Utils::gen_x509_object(pem) }.should raise_error( ZZZ::CA::Error )
    end
  end

  context "PEM のタイプを判別する場合" do
    it "::get_asn1_type(crl_pem) は :crl を返すこと" do
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
      ZZZ::CA::Utils::get_asn1_type(crl_pem).should == :crl
    end

    it "::get_asn1_type(pem) の pem が不正な書式の場合は例外を発生させること" do
     pem = <<-PEM
-----BEGIN X509 ZZZ-----
MIIBZTCBzwIBATANBgkqhkiG9w0BAQUFADBCMQswCQYDVQQDDAJDTjEOMAwGA1UE
CAwFVG9reW8xCjAIBgNVBAcMAUwxCzAJBgNVBAYTAkpQMQowCAYDVQQKDAFvFw0x
MDEwMjcxNDA1MDBaFw0xMDExMDMxNDA1MDBaMCgwEgIBGBcNMTAxMDI3MTQwNTAw
WjASAgEZFw0xMDEwMjcxNDA1MDBaoC8wLTAKBgNVHRQEAwIBEjAfBgNVHSMEGDAW
gBST1ffQ3NubF9S0zbA+Ih128OOt5TANBgkqhkiG9w0BAQUFAAOBgQCiFdMY8KRW
cL070DDfAIHWI/XaJEZ8qNlLfEU5SuQSRdv48PrVL2pXMyxd0nw5LC+BlXaaJ9vI
Uo/n76qbsYDFWsllACWBNLYuz4ZdBQjWRYX3sxanAko2w1F8Ka1GgKvwFI+o68SY
SedKdfhDSfXje1DPji8PMlEX2lMwvnYrmg==
-----END X509 ZZZ-----
      PEM
      lambda{ ZZZ::CA::Utils::get_asn1_type(pem) }.should raise_error( ZZZ::CA::Error )
    end
  end
end
