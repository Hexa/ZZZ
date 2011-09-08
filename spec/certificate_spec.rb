# -*- coding: utf-8 -*-

require 'rspec'
require 'time'
require 'openssl'
require 'zzz/ca/certificate'
require 'zzz/ca/error'
require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe ZZZ::CA::Certificate do
  before do
    @certificate_pem = <<-Certificate
-----BEGIN CERTIFICATE-----
MIIBzzCCATigAwIBAgIBFDANBgkqhkiG9w0BAQUFADANMQswCQYDVQQDDAJDQTAe
Fw0xMTA4MzExNTAwMDBaFw0xMTA5MjkxNTAwMDBaMA0xCzAJBgNVBAMMAkNBMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgIoRydXd8LDsXLmBPdAZmEtz39X90
J/3gQ7kHpq5uvEsz5aAaYL1LhAzzh+1eWUWMRbow6GNpJi1D8clpotv7MrRuQJTK
24G4SfxhPwiV+sGqekuF4PxhpH9riqMz8cOI6JrS7WnId4OEDxohdxlWUguqa9E1
TApdswaw3LO+9QIDAQAfoz8wPTAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIB
hjAdBgNVHQ4EFgQUr7brpp6rNl9YGj+eQp7iC0TFlFwwDQYJKoZIhvcNAQEFBQAD
gYEAulmDU7zJRmoDlUeHb7uWGolfWjD7dSZNPq645B+FVB2itA7C+ldZqAO96QV/
vTXAhVrGODwTvUwvmzQXUrLAMVOBcx3x5U/FicKNnKn2F0h/ryL+5ZukyV9wnVym
oV7SEHYKJVvmxZoherbS7eJ0k+LNCdOlaVu6GyfWfmYsjR8=
-----END CERTIFICATE-----
    Certificate
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

    @not_before = '2011-09-01 00:00:00 +0900'
    @not_after = '2011-09-30 00:00:00 +0900'
  end

  context "インスタンスを生成する場合" do
    before do
      module ZZZ; module CA; class Utils; end; end; end
    end

    it '::new はZZZ::CA::Certificate インスタンスを生成すること' do
      ZZZ::CA::Utils.should_receive(:new)
                    .with(:certificate, nil)
                    .and_return(OpenSSL::X509::Certificate.new)
      ZZZ::CA::Certificate.new.should be_an_instance_of ZZZ::CA::Certificate
    end

    it '::new(pem) はZZZ::CA::Certificate インスタンスを生成すること' do
      ZZZ::CA::Utils.should_receive(:new)
                    .with(:certificate, @certificate_pem)
                    .and_return(OpenSSL::X509::Certificate.new(@certificate_pem))
      ZZZ::CA::Certificate.new(@certificate_pem).should be_an_instance_of ZZZ::CA::Certificate
    end
  end

  context "インスタンスを生成した場合" do
    before do
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

      l = ->(subjects) do
        name = OpenSSL::X509::Name.new
        subjects.each do |e|
          e.each_pair do |key, value|
            name.add_entry(key, value)
          end
        end
        name
      end
      @ca_name = l.call(@ca_subject = [{'CN' => 'CA'}])
      @server_name = l.call(@server_subject = [{'CN' => 'Server'}])

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
      -> { @certificate.private_key = nil }.should raise_error ZZZ::CA::Error
    end

    it "#private_key=rsa_private_key （不正な PEM）を指定した場合は例外を発生させること" do
      ZZZ::CA::Utils.should_receive(:get_pkey_object)
                    .and_raise(ZZZ::CA::Error.new)
      -> { @certificate.private_key = 'invalid' }.should raise_error ZZZ::CA::Error
    end

    it "#encrypted_private_key は暗号化した Private Key を返すこと" do
      ZZZ::CA::Utils.should_receive(:get_pkey_object)
                    .with(@rsa_private_key_pem)
                    .and_return(OpenSSL::PKey::RSA.new(@rsa_private_key_pem))
      ZZZ::CA::Utils.should_receive(:cipher)
                    .with('AES-256-CBC')
                    .and_return(OpenSSL::Cipher::Cipher.new('AES-256-CBC'))
      @certificate.private_key = @rsa_private_key_pem
      @certificate.encrypted_private_key(:algorithm => 'AES-256-CBC', :passphrase => 'pass').should =~ /^-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,.+-----END RSA PRIVATE KEY-----$/m
    end

    it "#not_before='2011/09/01 00:00:00 +0900' を指定した後の #not_before は '2011/09/01 00:00:00 +0900' の Time オブジェクトを返すこと" do
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_before)
                    .and_return(Time.parse(@not_before))
      @certificate.not_before = @not_before
      @certificate.not_before.should == Time.parse(@not_before)
    end

    it "#not_after='2011/09/30 00:00:00 +0900' を指定した後の #not_after は '2011/09/30 00:00:00 +0900' の Time オブジェクトを返すこと" do
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_after)
                    .and_return(Time.parse(@not_after))
      @certificate.not_after = @not_after
      @certificate.not_after.should == Time.parse(@not_after)
    end

    it "#sign は ZZZ::CA::Certificate オブジェクトを返すこと" do
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_before)
                    .and_return(Time.parse(@not_before))
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_after)
                    .and_return(Time.parse(@not_after))
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@ca_subject)
                    .and_return(@ca_name)
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .and_return(@ca_name)
      @certificate.not_before = @not_before
      @certificate.not_after = @not_after
      @certificate.subject = @ca_subject
      @certificate.gen_private_key(params)
      @certificate.sign(:serial => 1).class.should == ZZZ::CA::Certificate
    end

    it "#sign(:version => 1) で署名した後の証明書のバージョンは 1 であること" do
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_before)
                    .and_return(Time.parse(@not_before))
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_after)
                    .and_return(Time.parse(@not_after))
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@ca_subject)
                    .and_return(@ca_name)
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .and_return(@ca_name)
      @certificate.not_before = @not_before
      @certificate.not_after = @not_after
      @certificate.subject = @ca_subject
      @certificate.gen_private_key(params)
      @certificate.sign(:serial => 1, :version => 1)
      @certificate.version.should == 1
    end

    it "#sign(:signer => ca) で CA が署名した後の証明書の発行者は署名した CA であること" do
      ca = double('signer')
      name = OpenSSL::X509::Name.new
      name.add_entry('CN', 'CA')
      ca.should_receive(:subject)
        .and_return(name)
      ca.should_receive(:private_key)
        .and_return(@rsa_private_key)
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_before)
                    .and_return(Time.parse(@not_before))
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_after)
                    .and_return(Time.parse(@not_after))
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@server_subject)
                    .and_return(@server_name)
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .and_return(@ca_name)
                    #.with(@ca_name)
      @certificate.not_before = @not_before
      @certificate.not_after = @not_after
      @certificate.subject = @server_subject
      @certificate.gen_private_key(params)
      @certificate.sign(:serial => 2, :signer => ca)
      @certificate.issuer.to_s.should == name.to_s
    end

    it "#signature_algorithm は #signature_algorithm= で指定したアルゴリズムを返すこと" do
      @certificate.signature_algorithm = 'MD5'
      @certificate.signature_algorithm.should == 'MD5'
      @certificate.signature_algorithm.should_not == 'SHA1'
    end

    it "#signature_algorithm は署名に使用したアルゴリズムを返すこと" do
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_before)
                    .and_return(Time.parse(@not_before))
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_after)
                    .and_return(Time.parse(@not_after))
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@ca_subject)
                    .and_return(@ca_name)
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .and_return(@ca_name)
      @certificate.not_before = @not_before
      @certificate.not_after = @not_after
      @certificate.subject = @ca_subject
      @certificate.gen_private_key(params)
      @certificate.sign(:serial => 1, :version => 1)
      @certificate.signature_algorithm.should == 'dsaWithSHA1'
    end

    it "#add_extension('oid', ['value1', 'value2'], critical = true}) を指定して、署名した後の証明書は指定した extension を含んでいること" do
      pending('ZZZ::CA::Utils::encode_extensions モックがエラーになるため')
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_before)
                    .and_return(Time.parse(@not_before))
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_after)
                    .and_return(Time.parse(@not_after))
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@ca_subject)
                    .and_return(@ca_name)
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .and_return(@ca_name)
      extensions = []
      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extensions << extension_factory.create_ext('basicConstraints', 'CA:TRUE, pathlen:1', true)
      extensions << extension_factory.create_ext('keyUsage', 'Certificate Sign, CRL Sign', false)
      extension_factory.subject_request = OpenSSL::X509::Request.new(@request_pem)
      extensions << extension_factory.create_ext('subjectKeyIdentifier', 'hash', false)
      ZZZ::CA::Utils.should_receive(:encode_extensions)
                    .at_least(:thrice)
                    .and_return(extensions)
      @certificate.not_before = @not_before
      @certificate.not_after = @not_after
      @certificate.subject = @ca_subject
      @certificate.subject_request = @request_pem
      @certificate.gen_private_key(params)

      @certificate.add_extension('basicConstraints', ['CA:TRUE', 'pathlen:1'], true)
      @certificate.add_extension('keyUsage', ['keyCertSign', 'cRLSign'])
      @certificate.add_extension('subjectKeyIdentifier', ['hash'])
      @certificate.sign(:serial => 1)
      @certificate.extensions.to_s.should == extensions.to_s
    end

    it "#extension = extensions を指定して、署名した後の証明書は指定した extension を含んでいること" do
      pending('ZZZ::CA::Utils::encode_extensions モックがエラーになるため')
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_before)
                    .and_return(Time.parse(@not_before))
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_after)
                    .and_return(Time.parse(@not_after))
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@ca_subject)
                    .and_return(@ca_name)
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      ZZZ::CA::Utils.should_receive(:gen_pkey)
                    .with(params)
                    .and_return(@dsa_private_key)
      extensions = []
      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extensions << extension_factory.create_ext('basicConstraints', 'CA:TRUE, pathlen:1', true)
      extensions << extension_factory.create_ext('keyUsage', 'Certificate Sign, CRL Sign', false)
      ZZZ::CA::Utils.should_receive(:encode_extensions)
                    .at_least(:thrice)
                    .and_return(extensions)
      @certificate.not_before = @not_before
      @certificate.not_after = @not_after
      @certificate.subject = @ca_subject
      @certificate.gen_private_key(params)
      extensions = {}
      extensions['basicConstraints'] = {:values => ['CA:TRUE', 'pathlen:1'], :critical => true}
      extensions['keyUsage'] = {:values => ['keyCertSign', 'cRLSign']}
      @certificate.extensions = extensions
      @certificate.sign(:serial => 1)
      @certificate.extensions.to_s.should == extensions.to_s
    end

    it do
      certificate = OpenSSL::X509::Certificate.new(@certificate_pem)
      ZZZ::CA::Utils.should_receive(:x509_object)
                    .with(:certificate, @certificate_pem)
                    .and_return(OpenSSL::X509::Certificate.new(@certificate_pem))
      @certificate.certificate = @certificate_pem
      @certificate.verify(@certificate.public_key).should be_true
    end

    it '#certificate = der は DER 形式の証明書を読み込めること' do
      certificate = OpenSSL::X509::Certificate.new(@certificate_pem)
      ZZZ::CA::Utils.should_receive(:x509_object)
                    .with(:certificate, certificate.to_der)
                    .and_return(OpenSSL::X509::Certificate.new(@certificate_pem))
      @certificate.certificate = certificate.to_der
      @certificate.certificate.should be_an_instance_of OpenSSL::X509::Certificate
    end

    it '#certificate = crl_der は例外を発生させること' do
      crl = OpenSSL::X509::CRL.new(@crl_pem)
      ZZZ::CA::Utils.should_receive(:x509_object)
                    .with(:certificate, crl.to_der)
                    .and_raise(OpenSSL::X509::CertificateError.new)
      -> { @certificate.certificate = crl.to_der }.should raise_error OpenSSL::X509::CertificateError 
    end

    it '#issuer_certificate は #issuer_certificate = pem で指定した PEM 形式の証明書を返すこと' do
      ZZZ::CA::Utils.should_receive(:x509_object)
                    .with(:certificate, @certificate_pem)
                    .and_return(OpenSSL::X509::Certificate.new(@certificate_pem))
      @certificate.issuer_certificate = @certificate_pem
      @certificate.issuer_certificate.should be_an_instance_of OpenSSL::X509::Certificate
      @certificate.issuer_certificate.to_pem.should == @certificate_pem
    end

    it '#subject_request は #subject_request = pem で指定した PEM 形式の CSR を返すこと' do
      ZZZ::CA::Utils.should_receive(:x509_object)
                    .with(:request, @request_pem)
                    .and_return(OpenSSL::X509::Request.new(@request_pem))
      @certificate.subject_request = @request_pem
      @certificate.subject_request.should be_an_instance_of OpenSSL::X509::Request
      @certificate.subject_request.to_pem.should == @request_pem
    end

    after do
      @certificate = nil
    end
  end

  after do
    @certificate_pem = nil
    @rsa_private_key_pem = nil
    @not_before = nil
    @not_after = nil
  end

  context '証明書を PKCS#12 にする場合' do
    it do
      certificate = ZZZ::CA::Certificate.new(@certificate_pem)
      certificate.private_key = @rsa_private_key_pem
      certificate.pkcs12('password').class.should == OpenSSL::PKCS12
    end
  end
end
