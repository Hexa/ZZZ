#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require 'rspec'
require 'ca/utils'
require 'time'
require 'openssl'

describe CA::Utils do
  context "インスタンスを生成する場合" do
    it ".new(:certificate) は OpenSSL::X509::Certificate オブジェクトを返すこと" do
      CA::Utils::new(:certificate).class.should == OpenSSL::X509::Certificate
    end

    it ".new(:request) は OpenSSL::X509::Request オブジェクトを返すこと" do
      CA::Utils::new(:request).class.should == OpenSSL::X509::Request
    end

    it ".new(:crl) は OpenSSL::X509::CRL オブジェクトを返すこと" do
      CA::Utils::new(:crl).class.should == OpenSSL::X509::CRL
    end
  end

  context "時間をエンコードする場合" do
    it ".encode_datetime(\"2011/05/10 00:00:00\") は 2011/05/10 00:00:00 の Time オブジェクトを返すこと" do
      datetime = "2011/05/10 00:00:00"
      CA::Utils::encode_datetime(datetime).should == Time.parse(datetime)
    end
  end

  context "" do
    it ".cipher(\"AES256\") は OpenSSL::Cipher::Cipher オブジェクトを返すこと" do
      CA::Utils::cipher("AES256").class.should == OpenSSL::Cipher::Cipher
    end
  end
end

