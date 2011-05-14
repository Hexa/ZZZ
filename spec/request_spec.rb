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

    it "#private_key=dsa_private_key を指定した後の #private_key は OpenSSL::PKey::DSA オブジェクトを返すこと" do

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

