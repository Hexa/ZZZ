# -*- coding: utf-8 -*-

require 'rspec'
require 'zzz/ca/x509'

describe ZZZ::CA::X509 do
  context "" do
    before do
      @x509 = ZZZ::CA::X509.new(:certificate)
    end

    it { ->{ @x509.sign(:invalid, '') }.should raise_error ZZZ::CA::Error }

    after do
      @x509 = nil
    end
  end
end
