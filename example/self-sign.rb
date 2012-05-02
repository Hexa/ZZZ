#!/usr/bin/env ruby
# -*- coding: utf-8 -*-

require 'zzz'

certificate = ZZZ::CA::Certificate.new
certificate.gen_private_key
certificate.not_before = Time.now
certificate.not_after = Time.now
certificate.add_subject('CN', 'CA')
certificate.subject_certificate = certificate.to_pem
certificate.add_extension('basicConstraints', ['CA:TRUE', 'pathlen:0'], true)
certificate.add_extension('keyUsage', ['keyCertSign', 'cRLSign'])
certificate.add_extension('extendedKeyUsage',
                          ['TLS Web Server Authentication',
                          'TLS Web Client Authentication'])
certificate.add_extension('subjectKeyIdentifier', ['hash'])
certificate.sign(:serial => 1)

puts certificate.to_text
puts certificate.to_pem
