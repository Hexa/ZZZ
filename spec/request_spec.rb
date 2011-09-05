#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require 'rspec'
require 'time'
require 'zzz/ca/request'

describe ZZZ::CA::Request do
  context "インスタンスを生成した場合" do
    before do
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
      @rsa_private_key_pem = <<-PrivateKey
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDgIoRydXd8LDsXLmBPdAZmEtz39X90J/3gQ7kHpq5uvEsz5aAa
YL1LhAzzh+1eWUWMRbow6GNpJi1D8clpotv7MrRuQJTK24G4SfxhPwiV+sGqekuF
4PxhpH9riqMz8cOI6JrS7WnId4OEDxohdxlWUguqa9E1TApdswaw3LO+9QIDAQAf
AoGBALKAoyhZCa36RL7DUAJeTvWg5Sip5TzQyBaH+2RRfzm/dVRijERIM9V2m9zi
3H7rjs3bWSzPnKF+Zt6gH3Gmik7G6ZBtcUu1i+eNtXU33ji0Yom0O1PjfL5NaMqF
8eUnDLg+9zm9GsYEhP4il1i8uBurverUoGlnKacPJUraSEJfAkEA+fVnrh5UDad7
ZaaLR7IGfVWlO0sl4YJXHaCAO7H7eGdbMSkSwT0Yu6/dByfX6doSFooYK2RBJ7oA
0tgCrhwxRQJBAOWNVIhKz1XVl73pQ3k5xRaGohfPWDCiBivR/r1bOcd0gETRtFeg
kjBLGy9L3u3rkiDRdXGx96SCYft4G8z9OfECQFolDuHXfD+5fGHHVhF8L6mnQZMJ
+P/Mq2HhtK+onE6t06yE67nJae60Ni8rO/0Ol85b6kMZ1hlGXxKPzN2/NecCQD65
dnKactJTmAgl1Dlk88OPx87ISJ8gRj9hD57nvk+XGfSro0Bfvd7tyXcclU9+EgKC
dQsUi3I6P7OELLgzu58CQChplIOFNunxqtCSPED629UjR6LFvg6PAV48clWE9sTp
kqgWcEQ1Y+kA7b85hBwmiWggUt6b073/Sg4PWXrkB40=
-----END RSA PRIVATE KEY-----
      PrivateKey
      @dsa_private_key = OpenSSL::PKey::DSA.new(@dsa_private_key_pem)
      @rsa_private_key = OpenSSL::PKey::RSA.new(@rsa_private_key_pem)
      @request = ZZZ::CA::Request.new
      @subject = [{'CN' => 'CA'}]
    end

    it "#private_key=dsa_private_key （PEM）を指定した後の #private_key は OpenSSL::PKey::DSA オブジェクトを返すこと" do
      ZZZ::CA::Utils.should_receive(:get_pkey_object)
                    .with(@dsa_private_key_pem)
                    .and_return(@dsa_private_key)
      @request.private_key = @dsa_private_key_pem
      @request.private_key.class.should == OpenSSL::PKey::DSA
    end

    it "#private_key=dsa_private_key （OpenSSL::PKey::DSA オブジェクト）を指定した後の #private_key は OpenSSL::PKey::DSA オブジェクトを返すこと" do
      @request.private_key = @dsa_private_key
      @request.private_key.class.should == OpenSSL::PKey::DSA
    end

    it "#private_key= に不正な値を指定した場合は例外を発生させること" do
      -> { @request.private_key = nil }.should raise_error ZZZ::CA::Error
    end

    it "#sign は ZZZ::CA::Request オブジェクトを返すこと" do
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      @request.subject = @subject
      @request.gen_private_key(params)
      @request.sign.class.should == ZZZ::CA::Request
    end

    it "#sign(:version => 0) で署名した後の CSR のバージョンは 0 であること " do
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      @request.subject = @subject
      @request.gen_private_key(params)
      @request.sign(:version => 0)
      @request.version.should == 0
    end

    it "#signature_algorithm は #signature_algorithm= で指定したアルゴリズムを返すこと" do
      @request.signature_algorithm = 'MD5'
      @request.signature_algorithm.should == 'MD5'
    end

    it "#signature_algorithm は署名に使用したアルゴリズムを返すこと" do
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      @request.subject = @subject
      @request.gen_private_key(params)
      @request.sign
      @request.signature_algorithm.should == 'dsaWithSHA1'
    end

    it "#request= request （PEM）を指定した後の #request は OpenSSL::X509::Request オブジェクトを返すこと" do
      request = OpenSSL::X509::Request.new(@request_pem)
      ZZZ::CA::Utils.should_receive(:x509_object)
                    .with(:request, @request_pem)
                    .and_return(request)
      @request.request = @request_pem
      @request.request.should be_an_instance_of OpenSSL::X509::Request
    end

    it "#request= request （OpenSSL::X509::Request オブジェクト）を指定した後の #request は OpenSSL::X509::Request オブジェクトを返すこと" do
      request = OpenSSL::X509::Request.new(@request_pem)
      ZZZ::CA::Utils.should_receive(:x509_object)
                    .with(:request, request)
                    .and_return(request)
      @request.request = request
      @request.request.should be_an_instance_of OpenSSL::X509::Request
    end

    it "#gen_private_key で秘密鍵を生成した後の #private_key は OpenSSL::PKey::RSA オブジェクトを返すこと" do
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                     .with({})
                     .and_return(@rsa_private_key)
      @request.gen_private_key
      @request.private_key.should be_an_instance_of OpenSSL::PKey::RSA
    end

    it "#gen_private_key(:public_key_algorithm => algorithm) の algorithm に不正な値を指定した場合は例外を発生させること" do
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                     .with(:public_key_algorithm => :ECDSA)
                     .and_raise(ZZZ::CA::Error.new)
      -> { @request.gen_private_key(:public_key_algorithm => :ECDSA) }.should raise_error ZZZ::CA::Error
    end

    after do
      @request = nil
      @request_pem = nil
      @dsa_private_key_pem = nil
      @rsa_private_key_pem = nil
      @dsa_private_key = nil
      @rsa_private_key = nil
      @subject = nil
    end
  end
end
