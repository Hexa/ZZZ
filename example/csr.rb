#!/usr/bin/env ruby
# -*- coding: utf-8 -*-

require 'zzz'

request = ZZZ::CA::Request.new
request.gen_private_key
request.add_subject('CN', 'Server')
request.sign
puts request.to_text
puts request.to_pem
