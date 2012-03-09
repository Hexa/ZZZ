# -*- coding: utf-8 -*-

require 'rspec'
require 'zzz/ca/extension_encoder'

describe ZZZ::CA::ExtensionEncoder do
  context 'Extension を ASN1 形式に変換するとき' do
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
      @request_pem = <<-Request
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
      Request
      @extension_encoder = ZZZ::CA::ExtensionEncoder.new
    end

    it '#show は追加されている oid, values を返すこと' do
      extensions = {
        'basicConstraints' => {
          :values => ['CA:TRUE', 'pathlen:0'], :critical => true},
        'keyUsage' => {
          :values => ['keyCertSign', 'cRLSign']},
        'extendedKeyUsage' => {
          :values => [
            'TLS Web Server Authentication',
            'TLS Web Client Authentication']}}
      extension_encoder = ZZZ::CA::ExtensionEncoder.new(extensions)
      extension_encoder.show.should == extensions
    end

    it '#show は追加されている oid (番号で指定する), values を返すこと' do
      extensions = {
        '2.16.840.1.113730.1.1' => {
          :values => ['01101101'], :critical => true, :type => :bit_string},
        '2.16.840.1.113730.1.13' => {
          :values => ['comment']}}
      extension_encoder = ZZZ::CA::ExtensionEncoder.new(extensions)
      extension_encoder.show.should == extensions
    end

    it '#show は追加されている oid, values を返すこと' do
      extensions = {
        'basicConstraints' => {
          :values => ['CA:TRUE', 'pathlen:0'], :critical => true},
        'keyUsage' => {
          :values => ['keyCertSign', 'cRLSign'], :critical => false},
        'extendedKeyUsage' => {
          :values => [
            'TLS Web Server Authentication',
            'TLS Web Client Authentication'], :critical => false}}
      @extension_encoder.add(:oid => 'basicConstraints', :values => ['CA:TRUE', 'pathlen:0'], :critical => true)
      @extension_encoder.add(:oid => 'keyUsage', :values => ['keyCertSign', 'cRLSign'])
      @extension_encoder.add(:oid => 'extendedKeyUsage', :values => [
        'TLS Web Server Authentication',
        'TLS Web Client Authentication'])
      @extension_encoder.show.should == extensions
    end

    it '#add は oid, value を追加すること' do
      extensions = {
        'basicConstraints' => {
          :values => ['CA:TRUE', 'pathlen:0'], :critical => false},
        'keyUsage' => {
          :values => ['keyCertSign', 'cRLSign'], :critical => false},
        'extendedKeyUsage' => {
          :values => [
            'TLS Web Server Authentication',
            'TLS Web Client Authentication'], :critical => false}}
      @extension_encoder.add(:oid => 'basicConstraints', :values => ['CA:TRUE', 'pathlen:0'], :critical => false)
      @extension_encoder.add(:oid => 'keyUsage', :values => ['keyCertSign', 'cRLSign'], :critical => false)
      @extension_encoder.add(:oid => 'extendedKeyUsage', :values => [
        'TLS Web Server Authentication',
        'TLS Web Client Authentication'])
      @extension_encoder.show.should == extensions
    end

    it '#delete は該当する oid を削除すること' do
      extensions = {
        'basicConstraints' => {
          :values => ['CA:TRUE', 'pathlen:0'], :critical => true}}
      @extension_encoder.add(:oid => 'basicConstraints', :values => ['CA:TRUE', 'pathlen:0'], :critical => true)
      @extension_encoder.add(:oid => 'keyUsage', :values => ['keyCertSign', 'cRLSign'])
      @extension_encoder.add(:oid => 'extendedKeyUsage', :values => [
        'TLS Web Server Authentication',
        'TLS Web Client Authentication'])
      @extension_encoder.delete('keyUsage')
      @extension_encoder.delete('extendedKeyUsage')
      @extension_encoder.show.should == extensions
    end

    it '#encode は add で追加した数の X509::Extension オブジェクトの配列を返すこと' do
      @extension_encoder.add(:oid => 'crlNumber', :values => [1])
      @extension_encoder.encode.should have(1).items
    end

    it '#encode は add で追加した数の X509::Extension オブジェクトの配列を返すこと' do
      @extension_encoder.add(:oid => 'basicConstraints', :values => ['CA:TRUE', 'pathlen:0'])
      @extension_encoder.add(:oid => 'keyUsage', :values => ['keyCertSign', 'cRLSign'])
      @extension_encoder.add(:oid => 'extendedKeyUsage', :values => [
        'TLS Web Server Authentication',
        'TLS Web Client Authentication'])
      @extension_encoder.encode.should have(3).items
    end

    it 'oid が CRLReson の場合に add で Extension を追加した後の #encode は 1 つの X509::Extension オブジェクトを返すこと' do
      @extension_encoder.add(:oid => 'CRLReason', :values => ['keyCompromise'], :type => :enumerated)
      @extension_encoder.encode.should be_an_instance_of OpenSSL::X509::Extension
    end

    it '#encode は OpenSSL::X509::Extension オブジェクトの配列を返すこと' do
      @extension_encoder.issuer_certificate = @certificate_pem
      @extension_encoder.subject_certificate = @certificate_pem
      @extension_encoder.add(:oid => 'basicConstraints', :values => ['CA:TRUE', 'pathlen:0'], :critical => true)
      @extension_encoder.add(:oid => 'keyUsage', :values => ['keyCertSign', 'cRLSign'])
      @extension_encoder.add(:oid => 'authorityKeyIdentifier', :values => ['keyid'], :critical => false)
      @extension_encoder.add(:oid => 'subjectKeyIdentifier', :values => ['hash'])
      @extension_encoder.add(:oid => 'extendedKeyUsage', :values => [
        'TLS Web Server Authentication',
        'TLS Web Client Authentication'])
      @extension_encoder.encode.should be_an_instance_of Array
    end

    it '#encoded_extensions は OpenSSL::X509::Extension オブジェクトの配列を返すこと' do
      @extension_encoder.add(:oid => '2.16.840.1.113730.1.1', :values => ['01001001'], :type => :bit_string)
      @extension_encoder.add(:oid => 'basicConstraints', :values => ['CA:TRUE', 'pathlen:0'], :critical => true)
      @extension_encoder.add(:oid => 'keyUsage', :values => ['keyCertSign', 'cRLSign'])
      @extension_encoder.add(:oid => '2.5.29.37', :values => ['01101100'], :type => :bit_string)
      @extension_encoder.encode
      @extension_encoder.encoded_extensions[rand(4)].should be_an_instance_of OpenSSL::X509::Extension
    end

    it '#encoded_extensions は OpenSSL::X509::Extension オブジェクトの配列を返すこと' do
      @extension_encoder.add(:oid => '2.5.29.19', :values => ['CA:TRUE'])
      @extension_encoder.add(:oid => '2.16.840.1.113730.1.1', :values => ['server', 'client'])
      @extension_encoder.encode
      @extension_encoder.encoded_extensions[rand(2)].should be_an_instance_of OpenSSL::X509::Extension
    end

    it '#add で不正な ASN.1 型を指定した場合の #encode は ZZZ::CA::Error Exception を返すこと' do
      @extension_encoder.add(:oid => '2.16.840.1.113730.1.13', :values => ['comment'], :type => :aaa)
      -> { @extension_encoder.encode }.should raise_error( ZZZ::CA::Error )
    end

    it '#encode の前の #encoded_extensions は空の配列を返すこと' do
      @extension_encoder.encoded_extensions.should be_an_instance_of Array
      @extension_encoder.encoded_extensions.should have(0).items
    end

    it '#subject_request= で CSR (PEM) を設定した後の #subject_request は OpenSSL::X509::Request オブジェクトを返すこと' do
      @extension_encoder.subject_request = @request_pem
      @extension_encoder.subject_request.should be_an_instance_of OpenSSL::X509::Request
    end

    it '#subject_request= で CSR (OpenSSL::X509::Request オブジェクト) を設定した後の #subject_request は OpenSSL::X509::Request オブジェクトを返すこと' do
      @extension_encoder.subject_request = OpenSSL::X509::Request.new(@request_pem)
      @extension_encoder.subject_request.should be_an_instance_of OpenSSL::X509::Request
    end

    it '#subject_request= で文字列または OpenSSL::X509::Request オブジェクト以外のオブジェクトを設定する場合は例外を返すこと' do
      -> { @extension_encoder.subject_request = 1 }.should raise_error( ZZZ::CA::Error )
    end

    it '#subject_certificate= で証明書 (PEM) を指定した後の #subject_certificate は OpenSSL::X509::Certificate を返すこと' do
      @extension_encoder.subject_certificate = @certificate_pem
      @extension_encoder.subject_certificate.should be_an_instance_of OpenSSL::X509::Certificate
    end

    it '#subject_certificate= で証明書 (OpenSSL::X509::Certificate オブジェクト) を指定した後の #subject_certificate は OpenSSL::X509::Certificate を返すこと' do
      @extension_encoder.subject_certificate = OpenSSL::X509::Certificate.new(@certificate_pem)
      @extension_encoder.subject_certificate.should be_an_instance_of OpenSSL::X509::Certificate
    end

    it '#issuer_certificate= で証明書 (PEM) を指定した後の #issuer_certificate は OpenSSL::X509::Certificate を返すこと' do
      @extension_encoder.issuer_certificate = @certificate_pem
      @extension_encoder.issuer_certificate.should be_an_instance_of OpenSSL::X509::Certificate
    end

    it '#issuer_certificate= で文字列または OpenSSL::X509::Certificate オブジェクト以外のオブジェクトを設定する場合は例外を返すこと' do
      -> { @extension_encoder.issuer_certificate = nil }.should raise_error( ZZZ::CA::Error )
    end

    it '#issuer_certificate= で証明書を指定した後の authorityKeyIdentifier を含んだ Extensions の #encode は OpenSSL::X509::Extension の配列を返すこと' do
      @extension_encoder.issuer_certificate = @certificate_pem
      @extension_encoder.add(:oid => 'authorityKeyIdentifier', :values => ['keyid'])
      @extension_encoder.encode[0].should be_an_instance_of OpenSSL::X509::Extension
    end

    it '#issuer_certificate= で証明書を指定した後の keyid 以外を指定した authorityKeyIdentifier を含んだ Extensions の #encode は OpenSSL::X509::ExtensionError Exception を返すこと' do
      @extension_encoder.issuer_certificate = @certificate_pem
      @extension_encoder.add(:oid => 'authorityKeyIdentifier', :values => ['key:id'])
      -> { @extension_encoder.encode }.should raise_error( OpenSSL::X509::ExtensionError )
    end

    it '#issuer_certificate= で証明書を指定した後の authorityKeyIdentifier を含んだ Extensions の #encode は authorityKeyIdentifier を含んだ配列を返すこと' do
      @extension_encoder.issuer_certificate = @certificate_pem
      @extension_encoder.add(:oid => 'authorityKeyIdentifier', :values => ['keyid'])
      @extension_encoder.encode[0].oid.should  == 'authorityKeyIdentifier'
    end

    it '証明書 (OpenSSL::X509::Certificate オブジェクト) を指定する前の authorityKeyIdentifier = keyid が追加された #encode は OpenSSL::X509::ExtensionError Exception を返すこと' do
      @extension_encoder.add(:oid => 'authorityKeyIdentifier', :values => ['keyid'])
      -> { @extension_encoder.encode }.should raise_error( OpenSSL::X509::ExtensionError )
    end

    after do
      @request_pem = nil
      @certificate_pem = nil
      @extension_encoder = nil
    end
  end
end
