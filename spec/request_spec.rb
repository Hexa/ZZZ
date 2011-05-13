#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require 'rspec'
require 'ca/utils'
require 'ca/request'
require 'time'

describe CA::Request do
  context "インスタンスを生成した場合" do
    before do
      @request = CA::Request.new
   end

    it "#sign は CA::Request オブジェクトを返すこと" do
      subject = [{'CN' => 'CA'}]
      @request.subject = subject
      @request.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      @request.sign.class.should == CA::Request
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

    after do
      @request = nil
    end
  end
end

