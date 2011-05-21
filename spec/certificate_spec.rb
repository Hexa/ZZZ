#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require 'rspec'
require 'time'
require 'zzz/ca/certificate'

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

    it "#sign(:version => 1) で署名した後の証明書のバージョンは 1 であること" do
      @certificate.not_before = '2010/09/21 00:00:00'
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      @certificate.subject = subject
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      @certificate.sign(:serial => 1, :version => 1)
      @certificate.version.should == 1
    end

    it "#sign(:signer => ca) で CA が署名した後の証明書の発行者は署名した CA であること" do
      ca = ZZZ::CA::Certificate.new
      ca.not_before = '2010/09/21 00:00:00'
      ca.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      ca.subject = subject
      ca.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :RSA)
      ca.sign(:serial => 1, :version => 1)

      @certificate.not_before = '2010/09/21 00:00:00'
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'Server'}]
      @certificate.subject = subject
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      @certificate.sign(:serial => 2, :signer => ca)
      @certificate.issuer.to_s.should == (OpenSSL::X509::Name.new).add_entry('CN', 'CA').to_s
    end

    it "#signature_algorithm は #signature_algorithm= で指定したアルゴリズムを返すこと" do
      @certificate.signature_algorithm = 'MD5'
      @certificate.signature_algorithm.should == 'MD5'
      @certificate.signature_algorithm.should_not == 'SHA1'
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

    it "#add_extension('oid', ['value1', 'value2'], critical = true}) を指定して、署名した後の証明書は指定した extension を含んでいること" do
      @certificate.not_before = '2010/09/21 00:00:00'
      @certificate.not_after = '2010/10/21 00:00:00'
      subject = [{'CN' => 'CA'}]
      @certificate.subject = subject
      @certificate.gen_private_key(:key_size => 1024, :exponent => 3, :public_key_algorithm => :DSA)
      @certificate.add_extension('basicConstraints', ['CA:TRUE', 'pathlen:1'], true)
      @certificate.add_extension('keyUsage', ['keyCertSign', 'cRLSign'])
      @certificate.sign(:serial => 1)

      extensions = []
      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extensions << extension_factory.create_ext('basicConstraints', 'CA:TRUE, pathlen:1', true)
      extensions << extension_factory.create_ext('keyUsage', 'Certificate Sign, CRL Sign', false)
      @certificate.extensions.to_s.should == extensions.to_s
    end

    after do
      @certificate = nil
    end
  end
end
