#!/usr/bin/env ruby
# -*- coding: utf-8 -*-

require 'zzz'

certificate = ZZZ::CA::Certificate.new
certificate.gen_private_key(:key_size => 2048,
                            :exponent => 65537,
                            :public_key_algorithm => :RSA)
certificate.not_before = Time.now.to_s
certificate.not_after = '2012/01/01 09:00:00 +0900'
certificate.add_subject('CN', 'example.com')
certificate.subject_certificate = certificate.to_pem
certificate.add_extension('basicConstraints', ['CA:TRUE'], true)
certificate.add_extension('keyUsage', ['keyCertSign', 'cRLSign'])
certificate.add_extension('subjectKeyIdentifier', ['hash'])
certificate.sign(:serial => 1)
puts certificate.to_text
puts certificate.to_pem
