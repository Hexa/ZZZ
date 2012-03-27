# -*- coding: utf-8 -*-

require 'rspec'
require 'zzz/ca/certificate'

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
    @rsa_private_key = OpenSSL::PKey::RSA.new(@rsa_private_key_pem)
  end

  context "" do
    before do
      l = ->(subjects) do
        name = OpenSSL::X509::Name.new
        subjects.each {|e| e.each_pair {|key, value| name.add_entry(key, value) }}
        name
      end
      e = (0x21..0x7e).to_a.map {|e| e.chr }
      cn = Array.new(rand(100)).map { e[rand(e.length)] }.join('')
      @server_name = l.call([{'CN' => cn}])

      ## "subjectAltName", "DNS:foo.example.com"
      ## "subjectAltName", "DNS:bar.example.com"
      @subject_alt_name1 = ["301a0603551d1104133011820f666f6f2e6578616d706c652e636f6d"].pack('H*')
      @subject_alt_name2 = ["301a0603551d1104133011820f6261722e6578616d706c652e636f6d"].pack('H*')
      @request = double('request')
    end

    it "::find_ext_request(request) は OpenSSL::ASN1 オブジェクトの配列を返すこと" do
      attribute1 = double('attribute1')
      attribute1.should_receive(:oid)
                .exactly(3).times
                .and_return(nil)
      attribute2 = double('attribute2')
      attribute2.should_receive(:oid)
                .exactly(3).times
                .and_return('extReq')
      attribute2.should_receive(:nil?)
                .and_return(false)
      @request.should_receive(:attributes)
              .exactly(3).times
              .and_return([attribute1, attribute2])
      values = double('values')
      values.should_receive(:value)
            .exactly(3).times
            .and_return([[
                        OpenSSL::ASN1.decode(@subject_alt_name1),
                        OpenSSL::ASN1.decode(@subject_alt_name2)]])
      attribute2.should_receive(:value)
                .exactly(3).times
                .and_return(values)
      ZZZ::CA::Certificate.find_ext_request(@request).should be_instance_of Array
      ZZZ::CA::Certificate.find_ext_request(@request)[0].should be_instance_of OpenSSL::ASN1::Sequence
      ZZZ::CA::Certificate.find_ext_request(@request)[1].should be_instance_of OpenSSL::ASN1::Sequence
    end

    it "::set_extensions(certificate, request) は OpenSSL::X509::Extension オブジェクトの配列を返すこと" do
      extension1 = double('extension1')
      extension1.should_receive(:to_der)
                .and_return(@subject_alt_name1)
      extension2 = double('extension2')
      extension2.should_receive(:to_der)
                .and_return(@subject_alt_name2)
      ZZZ::CA::Certificate.should_receive(:find_ext_request)
                          .with(@request)
                          .and_return([extension1, extension2])
      ZZZ::CA::Certificate.find_extensions(@request).should be_instance_of Array
    end

    it "::set_request(signed_request) は ZZZ::CA::Certificate オブジェクトを返すこと" do
      @request.should_receive(:private_key)
                    .and_return(@rsa_private_key)
      @request.should_receive(:public_key)
                    .and_return(@rsa_private_key.public_key)
      @request.should_receive(:subject)
                    .and_return(@server_name)
      @request.should_receive(:to_pem)
                    .and_return(@request_pem)
      extensions = {
        "subjectAltName" => {
          :values => ["DNS:foo.example.com", "DNS:bar.example.com"]}}
      ZZZ::CA::Certificate.should_receive(:find_extensions)
                          .with(@request)
                          .and_return(extensions)
      ZZZ::CA::Certificate.set_request(@request).should be_instance_of ZZZ::CA::Certificate
    end

    after do
      @request = nil
      @server_name = nil
      @signed_request = nil
    end
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
      l = ->(subjects) do
        name = OpenSSL::X509::Name.new
        subjects.each {|e| e.each_pair {|key, value| name.add_entry(key, value) }}
        name
      end

      e = (0x21..0x7e).to_a.map {|e| e.chr }
      cn = Array.new(rand(100)).map { e[rand(e.length)] }.join('')
      @ca_name = l.call(@ca_subject = [{'CN' => cn}])
      cn = Array.new(rand(100)).map { e[rand(e.length)] }.join('')
      @server_name = l.call(@server_subject = [{'CN' => cn}])

      ZZZ::CA::Utils.should_receive(:new)
                    .at_least(:once)
                    .and_return(OpenSSL::X509::Certificate.new)
      @certificate = ZZZ::CA::Certificate.new
      @not_before = '2011-09-01 00:00:00 +0900'
      @not_after = '2011-09-30 00:00:00 +0900'
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
      ZZZ::CA::Utils.should_receive(:pkey_object)
                    .with(@rsa_private_key_pem)
                    .and_return(@rsa_private_key)
      @certificate.private_key = @rsa_private_key_pem
      @certificate.private_key.should be_an_instance_of OpenSSL::PKey::RSA
    end

    it "#private_key=rsa_private_key （OpenSSL::PKey::RSA オブジェクト）を指定した後の #private_key は OpenSSL::PKey::RSA オブジェクトを返すこと" do
      @certificate.private_key = @rsa_private_key
      @certificate.private_key.should be_an_instance_of OpenSSL::PKey::RSA
    end

    it "#private_key=nil の場合は例外を発生させること" do
      -> { @certificate.private_key = nil }.should raise_error ZZZ::CA::Error
    end

    it "#private_key=rsa_private_key （不正な PEM）を指定した場合は例外を発生させること" do
      ZZZ::CA::Utils.should_receive(:pkey_object)
                    .and_raise(ZZZ::CA::Error)
      -> { @certificate.private_key = 'invalid' }.should raise_error ZZZ::CA::Error
    end

    it "#encrypted_private_key は暗号化した Private Key を返すこと" do
      ZZZ::CA::Utils.stub!(:pkey_object)
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
      ZZZ::CA::Utils.stub!(:encode_subject)
                    .and_return(@ca_name)
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_before)
                    .and_return(Time.parse(@not_before))
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_after)
                    .and_return(Time.parse(@not_after))
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@ca_subject)
                    .and_return(@ca_name)
      ZZZ::CA::Utils.stub!(:gen_pkey)
                    .and_return(@dsa_private_key)
      @certificate.not_before = @not_before
      @certificate.not_after = @not_after
      @ca_subject.each do |e|
        e.each_pair do |oid, value|
          @certificate.add_subject(oid, value)
        end
      end
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      @certificate.gen_private_key(params)
      @certificate.sign(:serial => 1).should be_an_instance_of ZZZ::CA::Certificate
    end

    it "#sign(:version => 1) で署名した後の証明書のバージョンは 1 であること" do
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_before)
                    .and_return(Time.parse(@not_before))
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_after)
                    .and_return(Time.parse(@not_after))
      ZZZ::CA::Utils.stub!(:encode_subject)
                    .and_return(@ca_name)
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@ca_subject)
                    .and_return(@ca_name)
      ZZZ::CA::Utils.stub!(:gen_pkey)
                    .and_return(@dsa_private_key)
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      @certificate.not_before = @not_before
      @certificate.not_after = @not_after
      @ca_subject.each do |e|
        e.each_pair do |oid, value|
          @certificate.add_subject(oid, value)
        end
      end
      @certificate.gen_private_key(params)
      @certificate.sign(:serial => 1, :version => 1)
      @certificate.version.should == 1
    end

    it "#sign(:signer => ca) で CA が署名した後の証明書の発行者は署名した CA であること" do
      ca = double('signer')
      ca.should_receive(:subject)
        .and_return(@ca_name)
      ca.should_receive(:private_key)
        .and_return(@rsa_private_key)
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_before)
                    .and_return(Time.parse(@not_before))
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_after)
                    .and_return(Time.parse(@not_after))
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@server_subject)
                    .and_return(@server_name)
      ZZZ::CA::Utils.stub!(:gen_pkey)
                    .and_return(@dsa_private_key)
      @certificate.not_before = @not_before
      @certificate.not_after = @not_after
      @server_subject.each do |e|
        e.each_pair do |oid, value|
          @certificate.add_subject(oid, value)
        end
      end
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      @certificate.gen_private_key(params)
      @certificate.sign(:serial => 2, :signer => ca)
      @certificate.issuer.to_s.should == @ca_name.to_s
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
      ZZZ::CA::Utils.stub!(:encode_subject)
                    .and_return(@ca_name)
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@ca_subject)
                    .and_return(@ca_name)
      ZZZ::CA::Utils.stub!(:gen_pkey)
                    .and_return(@dsa_private_key)
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      @certificate.not_before = @not_before
      @certificate.not_after = @not_after
      @ca_subject.each do |e|
        e.each_pair do |oid, value|
          @certificate.add_subject(oid, value)
        end
      end
      @certificate.gen_private_key(params)
      @certificate.sign(:serial => 1, :version => 1)
      @certificate.signature_algorithm.should == 'dsaWithSHA1'
    end

    it "#extension = extensions を指定して、署名した後の証明書は指定した extension を含んでいること" do
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_before)
                    .and_return(Time.parse(@not_before))
      ZZZ::CA::Utils.should_receive(:encode_datetime)
                    .with(@not_after)
                    .and_return(Time.parse(@not_after))
      ZZZ::CA::Utils.stub!(:encode_subject)
                    .and_return(@ca_name)
      ZZZ::CA::Utils.should_receive(:encode_subject)
                    .with(@ca_subject)
                    .and_return(@ca_name)
      request = OpenSSL::X509::Request.new(@request_pem)
      ZZZ::CA::Utils.stub!(:x509_object)
                    .and_return(request)
      ZZZ::CA::Utils.stub!(:gen_pkey)
                    .and_return(@dsa_private_key)
      extensions = []
      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extensions << extension_factory.create_ext('basicConstraints', 'CA:TRUE, pathlen:1', true)
      extensions << extension_factory.create_ext('keyUsage', 'Certificate Sign, CRL Sign', false)
      extension_factory.subject_request = request
      extensions << extension_factory.create_ext('subjectKeyIdentifier', 'hash', false)
      ZZZ::CA::Utils.should_receive(:encode_extensions)
                    .exactly(1).times
                    .and_return(extensions)
      ZZZ::CA::Utils.stub!(:encode_subject)
                    .and_return(@ca_name)
      params = {:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA}
      @certificate.not_before = @not_before
      @certificate.not_after = @not_after
      @ca_subject.each do |e|
        e.each_pair do |oid, value|
          @certificate.add_subject(oid, value)
        end
      end
      @certificate.subject_request = @request_pem
      @certificate.gen_private_key(params)
      @certificate.extensions = {
        'basicConstraints' => {
          :values => ['CA:TRUE', 'pathlen:1'], :critical => true},
        'keyUsage' => {
          :values => ['keyCertSign', 'cRLSign']},
        'subjectKeyIdentifier' => {
          :values => ['hash'], :critical => false, :invalid => false}}
      @certificate.sign(:serial => 1)
      @certificate.extensions.to_s.should == extensions.to_s
    end

    it do
      ZZZ::CA::Utils.should_receive(:x509_object)
                    .with(:certificate, @certificate_pem)
                    .and_return(OpenSSL::X509::Certificate.new(@certificate_pem))
      certificate = OpenSSL::X509::Certificate.new(@certificate_pem)
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

    it "#certificate = crl_der は例外を発生させること" do
      crl = OpenSSL::X509::CRL.new(@crl_pem)
      ZZZ::CA::Utils.should_receive(:x509_object)
                    .with(:certificate, crl.to_der)
                    .and_raise(OpenSSL::X509::CertificateError.new)
      -> { @certificate.certificate = crl.to_der }.should raise_error OpenSSL::X509::CertificateError 
    end

    it "#issuer_certificate は #issuer_certificate = pem で指定した PEM 形式の証明書を返すこと" do
      ZZZ::CA::Utils.should_receive(:x509_object)
                    .with(:certificate, @certificate_pem)
                    .and_return(OpenSSL::X509::Certificate.new(@certificate_pem))
      @certificate.issuer_certificate = @certificate_pem
      @certificate.issuer_certificate.should be_an_instance_of OpenSSL::X509::Certificate
      @certificate.issuer_certificate.to_pem.should == @certificate_pem
    end

    it "#subject_request は #subject_request = pem で指定した PEM 形式の CSR を返すこと" do
      ZZZ::CA::Utils.should_receive(:x509_object)
                    .with(:request, @request_pem)
                    .and_return(OpenSSL::X509::Request.new(@request_pem))
      @certificate.subject_request = @request_pem
      @certificate.subject_request.should be_an_instance_of OpenSSL::X509::Request
      @certificate.subject_request.to_pem.should == @request_pem
    end

    after do
      @certificate = nil
      @ca_name = nil
      @server_name = nil
      @not_before = nil
      @not_after = nil
    end
  end

  context "証明書を PKCS#12 で取得する場合" do
    it "#pkcs12(password) は OpenSSL::PKCS12 オブジェクトを返すこと" do
      ZZZ::CA::Utils.stub!(:new)
                    .and_return(OpenSSL::X509::Certificate.new(@certificate_pem))
      ZZZ::CA::Utils.should_receive(:pkey_object)
                    .with(@rsa_private_key_pem)
                    .and_return(@rsa_private_key)
      certificate = ZZZ::CA::Certificate.new(@certificate_pem)
      certificate.private_key = @rsa_private_key_pem
      certificate.pkcs12('password').should be_an_instance_of OpenSSL::PKCS12
    end
  end

  context "証明書を PKCS#12 に変換する場合" do
    before do
      @passphrase = 'passphrase'
    end

    it "::pkcs12(passphrase, certificate, private_key) は OpenSSL::PKCS12 を返すこと" do
      certificate = OpenSSL::X509::Certificate.new(@certificate_pem)
      ZZZ::CA::Certificate.pkcs12(@passphrase, certificate, @rsa_private_key).should be_instance_of OpenSSL::PKCS12
    end

    it "::pkcs12(passphrase, certificate) は OpenSSL::PKCS12::PKCS12Error を返すこと" do
      certificate = OpenSSL::X509::Certificate.new(@certificate_pem)
      certificate = OpenSSL::X509::Certificate.new(@certificate_pem)
      -> { ZZZ::CA::Certificate.pkcs12(@passphrase, certificate) }.should raise_error OpenSSL::PKCS12::PKCS12Error
    end

    it "::pkcs12(passphrase, certificate, private_key) は OpenSSL::PKCS12 を返すこと" do
      certificate = ZZZ::CA::Certificate.new(@certificate_pem)
      ZZZ::CA::Certificate.pkcs12(@passphrase, certificate, @rsa_private_key).should be_instance_of OpenSSL::PKCS12
    end

    it "::pkcs12(passphrase, certificate) は OpenSSL::PKCS12 を返すこと" do
      certificate = ZZZ::CA::Certificate.new(@certificate_pem)
      certificate.private_key = @rsa_private_key
      ZZZ::CA::Certificate.pkcs12(@passphrase, certificate).should be_instance_of OpenSSL::PKCS12
    end

    it "::pkcs12(passphrase, certificate) は ZZZ::CA::Error を返すこと" do
      certificate = ZZZ::CA::Certificate.new(@certificate_pem)
      -> { ZZZ::CA::Certificate.pkcs12(@passphrase, certificate) }.should raise_error ZZZ::CA::Error
    end

    it "::pkcs12(passphrase, 'string') は ZZZ::CA::Error を返すこと" do
      -> { ZZZ::CA::Certificate.pkcs12(@passphrase, 'string') }.should raise_error ZZZ::CA::Error
    end

    after do
      @passphrase = nil
    end
  end

  after do
    @certificate_pem = nil
    @rsa_private_key_pem = nil
    @dsa_private_key = nil
    @rsa_private_key = nil
  end
end
