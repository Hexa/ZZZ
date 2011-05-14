#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require 'rspec'
require 'zzz/ca/utils'
require 'zzz/ca/certificate'
require 'time'

describe ZZZ::CA::Certificate do
  context "インスタンスを生成した場合" do
    before do
      @certificate = ZZZ::CA::Certificate.new
   end

    it "#gen_private_key は RAS Private Key を返すこと" do
      @certificate.gen_private_key.to_s.should =~ /^-----BEGIN RSA PRIVATE KEY-----.+-----END RSA PRIVATE KEY-----$/m
    end

    it "#gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA) は DSA Private Key を返すこと" do
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA).to_s.should =~ /^-----BEGIN DSA PRIVATE KEY-----.+-----END DSA PRIVATE KEY-----$/m
    end

    it "#private_key=rsa_private_key を指定した後の #private_key は OpenSSL::PKey::RSA オブジェクトを返すこと" do
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
      @certificate.private_key = rsa_private_key
      @certificate.private_key.class.should == OpenSSL::PKey::RSA
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

    it "#sign は ZZZ::CA::Certificate オブジェクトを返すこと" do
      @certificate.not_before = '2010/09/21 00:00:00'
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      @certificate.subject = subject
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      @certificate.sign(:serial => 1).class.should == ZZZ::CA::Certificate
    end

    it "#signature_algorithm は #signature_algorithm= で指定したアルゴリズムを返すこと" do
      @certificate.signature_algorithm = 'MD5'
      @certificate.signature_algorithm.should == 'MD5'
    end

    it "#signature_algorithm は署名に使用したアルゴリズムを返すこと" do
      @certificate.not_before = '2010/09/21 00:00:00'
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      @certificate.subject = subject
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      @certificate.sign(:serial => 1)
      @certificate.signature_algorithm.should == 'dsaWithSHA1'
    end

    after do
      @certificate = nil
    end
  end
end

