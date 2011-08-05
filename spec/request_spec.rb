#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require 'rspec'
require 'time'
require 'zzz/ca/request'

describe ZZZ::CA::Request do
  context "インスタンスを生成した場合" do
    before do
      @request = ZZZ::CA::Request.new
   end

    it "#private_key=dsa_private_key （PEM）を指定した後の #private_key は OpenSSL::PKey::DSA オブジェクトを返すこと" do

      dsa_private_key = <<-PrivateKey
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
      @request.private_key = dsa_private_key
      @request.private_key.class.should == OpenSSL::PKey::DSA
    end

    it "#private_key=dsa_private_key （OpenSSL::PKey::DSA オブジェクト）を指定した後の #private_key は OpenSSL::PKey::DSA オブジェクトを返すこと" do
      dsa_private_key = <<-PrivateKey
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
      @request.private_key = OpenSSL::PKey::DSA.new(dsa_private_key)
      @request.private_key.class.should == OpenSSL::PKey::DSA
    end

    it "#private_key= に不正な値を指定した場合は例外を発生させること" do
      lambda { @request.private_key = nil }.should raise_error ZZZ::CA::Error
    end

    it "#sign は ZZZ::CA::Request オブジェクトを返すこと" do
      subject = [{'CN' => 'CA'}]
      @request.subject = subject
      @request.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      @request.sign.class.should == ZZZ::CA::Request
    end

    it "#sign(:version => 0) で署名した後の CSR のバージョンは 0 であること " do
      subject = [{'CN' => 'CA'}]
      @request.subject = subject
      @request.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      @request.sign(:version => 0)
      @request.version.should == 0
    end

    it "#signature_algorithm は #signature_algorithm= で指定したアルゴリズムを返すこと" do
      @request.signature_algorithm = 'MD5'
      @request.signature_algorithm.should == 'MD5'
    end

    it "#signature_algorithm は署名に使用したアルゴリズムを返すこと" do
      subject = [{'CN' => 'CA'}]
      @request.subject = subject
      @request.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      @request.sign
      @request.signature_algorithm.should == 'dsaWithSHA1'
    end

    it "#request= request （PEM）を指定した後の #request は OpenSSL::X509::Request オブジェクトを返すこと" do
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
      @request.request = request
      @request.request.should be_an_instance_of OpenSSL::X509::Request
    end

    it "#request= request （OpenSSL::X509::Request オブジェクト）を指定した後の #request は OpenSSL::X509::Request オブジェクトを返すこと" do
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
      @request.request = OpenSSL::X509::Request.new(request)
      @request.request.should be_an_instance_of OpenSSL::X509::Request
    end

    it "#gen_private_key で秘密鍵を生成した後の #private_key は OpenSSL::PKey::RSA オブジェクトを返すこと" do
      @request.gen_private_key
      @request.private_key.should be_an_instance_of OpenSSL::PKey::RSA
    end

    it "#gen_private_key(:public_key_algorithm => algorithm) の algorithm に不正な値を指定した場合は例外を発生させること" do
      lambda { @request.gen_private_key(:public_key_algorithm => :ECDSA) }.should raise_error ZZZ::CA::Error
    end

    after do
      @request = nil
    end
  end
end
