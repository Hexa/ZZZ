#!/usr/bin/env ruby
# -*- coding: utf-8 -*-

require 'zzz'

ca = ZZZ::CA::Certificate.new
ca.gen_private_key
ca.not_before = Time.now
ca.not_after = Time.now
ca.add_subject('CN', 'CA')
ca.subject_certificate = ca.to_pem
ca.add_extension('basicConstraints', ['CA:TRUE', 'pathlen:0'], true)
ca.add_extension('keyUsage', ['keyCertSign', 'cRLSign'])
ca.add_extension('extendedKeyUsage',
                  ['TLS Web Server Authentication',
                    'TLS Web Client Authentication'])
ca.add_extension('subjectKeyIdentifier', ['hash'])
ca.sign(:serial => 1)


request = ZZZ::CA::Request.new
request.gen_private_key
request.add_subject('CN', 'Server')
request.sign

certificate = ZZZ::CA::Certificate.new
certificate.private_key = request.private_key
certificate.public_key = request.public_key
certificate.not_before = Time.now
certificate.not_after = Time.now
certificate.subject = request.subject
certificate.issuer_certificate = ca.to_pem
certificate.subject_certificate = certificate.to_pem
certificate.add_extension('basicConstraints', ['CA:FALSE'])
certificate.add_extension('authorityKeyIdentifier', ['keyid:true'])
certificate.add_extension('subjectKeyIdentifier', ['hash'])
certificate.add_extension('extendedKeyUsage',
                          ['TLS Web Server Authentication',
                            'TLS Web Client Authentication'])
certificate.sign(:serial => 2, :signer => ca)


puts certificate.to_text
puts certificate.to_pem
