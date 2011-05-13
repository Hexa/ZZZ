#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require 'rspec'
require 'ca/utils'
require 'ca/certificate'
require 'time'

describe CA::Certificate do
  context "インスタンスを生成した場合" do
    before do
      @certificate = CA::Certificate.new
   end

    it "#gen_private_key は RAS Private Key を返すこと" do
      @certificate.gen_private_key.to_s.should =~ /^-----BEGIN RSA PRIVATE KEY-----.+-----END RSA PRIVATE KEY-----$/m
    end

    it "#gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA) は DSA Private Key を返すこと" do
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA).to_s.should =~ /^-----BEGIN DSA PRIVATE KEY-----.+-----END DSA PRIVATE KEY-----$/m
    end

    it "#private_key=(rsa_private_key) は OpenSSL::PKey::RSA オブジェクトを返すこと" do
    end

    it "#not_before='2011/05/10 00:00:00' を指定した後の #not_before は '2010/09/21 00:00:00' の Time オブジェクトを返すこと" do
      time = '2010/09/21 00:00:00'
      @certificate.not_before = time
      @certificate.not_before.should == Time.parse(time)
    end

    it "#not_after='2011/05/10 00:00:00' を指定した後の #not_after は '2010/09/21 00:00:00' の Time オブジェクトを返すこと" do
      time = '2010/09/21 00:00:00'
      @certificate.not_after = time
      @certificate.not_after.should == Time.parse(time)
    end

    it "#sign は CA::Certificate オブジェクトを返すこと" do
      @certificate.not_before = '2010/09/21 00:00:00'
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      @certificate.subject = subject
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA).to_s.should =~ /^-----BEGIN DSA PRIVATE KEY-----.+-----END DSA PRIVATE KEY-----$/m
      @certificate.sign(:serial => 1).class.should == CA::Certificate
    end

    it "#signature_algorithm は #signature_algorithm= で指定したアルゴリズムを返すこと" do
      @certificate.signature_algorithm = 'MD5'
      @certificate.signature_algorithm.should == 'MD5'
    end

    it "#signature_algorithm は署名に使用したアルゴリズムを返すこと" do
      pending
      @certificate.not_before = '2010/09/21 00:00:00'
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      @certificate.subject = subject
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA).to_s.should =~ /^-----BEGIN DSA PRIVATE KEY-----.+/m
      @certificate.sign(:serial => 1)
      @certificate.signature_algorithm.should == 'dsaWithSHA1'
    end

    after do
      @certificate = nil
    end
  end
end

