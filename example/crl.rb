#!/usr/bin/env ruby
# -*- coding: utf-8 -*-

require 'zzz'

certificate = ZZZ::CA::Certificate.new
certificate.gen_private_key
certificate.not_before = Time.now 
certificate.not_after = Time.now
certificate.add_subject('CN', 'CA')
certificate.add_extension('basicConstraints', ['CA:TRUE', 'pathlen:0'], true)
certificate.add_extension('keyUsage', ['keyCertSign', 'cRLSign'])
certificate.add_extension('crlDistributionPoints', ['URI:http://example.com/example.crl'])
certificate.add_extension('extendedKeyUsage',
                          ['TLS Web Server Authentication',
                          'TLS Web Client Authentication'])
certificate.sign(:serial => 1)


crl = ZZZ::CA::CRL.new
crl.last_update = Time.now
crl.next_update = Time.now
crl.add_revoked(:serial => 1, :datetime => Time.now.to_s,
                              :reason => 'superseded')
crl.add_revoked(:serial => 2, :datetime => Time.now.to_s)
crl.add_revoked(:serial => 3, :datetime => Time.now.to_s,
                              :reason => 'cACompromise')

crl.sign(:signer => certificate)


puts crl.to_text
puts crl.to_pem
