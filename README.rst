===
ZZZ
===

:Author: Hexa
:Mail:  hexa.diary@gmail.com
:License: New BSD License


DESCRIPTION
===========

証明書発行ライブラリです．

証明書，CSR，CRL の作成が可能です．


INSTALL
=======

最新のソースコードは下記のリポジトリから取得可能です．
::

  git://github.com/Hexa/ZZZ.git

インストール
::

  $ rake build
  $ gem install pkg/ZZZ-<version>.gem


REQUIREMENTS
============

- ruby 1.9.2
- OpenSSL 1.0.0


SAMPLE
======

CSR
---

CSR の作成
::

  require 'zzz'
  include ZZZ::CA

  request = Request.new
  request.gen_private_key
  request.add_subject('C', 'JP')
  request.add_subject('ST', 'Tokyo')
  request.add_subject('L', 'Chuo')
  request.add_subject('O', 'O')
  request.add_subject('CN', 'Server')
  request.sign
  puts request.to_text


証明書
------

ルート CA 証明書の作成
::

  require 'zzz'
  include ZZZ::CA

  certificate = Certificate.new
  certificate.gen_private_key
  certificate.not_before = '2010/09/21 00:00:00'
  certificate.not_after = '2010/10/21 00:00:00'
  certificate.add_subject('C', 'JP')
  certificate.add_subject('ST', 'Tokyo')
  certificate.add_subject('L', 'Chuo')
  certificate.add_subject('O', 'O')
  certificate.add_subject('CN', 'CA')
  certificate.add_extension('basicConstraints', ['CA:TRUE', 'pathlen:0'], true)
  certificate.add_extension('keyUsage', ['keyCertSign', 'cRLSign'])
  certificate.add_extension('extendedKeyUsage',
                            ['TLS Web Server Authentication',
                            'TLS Web Client Authentication'])
  certificate.sign(:serial => 1)
  puts certificate.to_text


証明書の作成
::

  require 'zzz'
  include ZZZ::CA

  ca = Certificate.new
  ca.gen_private_key
  ca.not_before = '2010/09/21 00:00:00'
  ca.not_after = '2010/10/21 00:00:00'
  ca.add_subject('C', 'JP')
  ca.add_subject('ST', 'Tokyo')
  ca.add_subject('L', 'Chuo')
  ca.add_subject('O', 'O')
  ca.add_subject('CN', 'CA')
  ca.add_extension('basicConstraints', ['CA:TRUE', 'pathlen:0'], true)
  ca.add_extension('keyUsage', ['keyCertSign', 'cRLSign'])
  ca.add_extension('extendedKeyUsage',
                    ['TLS Web Server Authentication',
                    'TLS Web Client Authentication'])
  ca.sign(:serial => 1)

  request = Request.new
  request.gen_private_key
  request.add_subject('C', 'JP')
  request.add_subject('ST', 'Tokyo')
  request.add_subject('L', 'Chuo')
  request.add_subject('O', 'O')
  request.add_subject('CN', 'Server')
  request.sign
  puts request.to_text

  certificate = Certificate.new
  certificate.private_key = request.private_key
  certificate.public_key = request.public_key
  certificate.not_before = '2010/09/21 00:00:00'
  certificate.not_after = '2010/10/21 00:00:00'
  certificate.subject = request.subject
  certificate.issuer_certificate = ca.to_pem
  certificate.subject_request = request.to_pem
  certificate.add_extension('basicConstraints', ['CA:FALSE'])
  certificate.add_extension('authorityKeyIdentifier', ['keyid:true'])
  certificate.add_extension('subjectKeyIdentifier', ['hash'])
  certificate.add_extension('extendedKeyUsage',
                            ['TLS Web Server Authentication',
                              'TLS Web Client Authentication'])
  certificate.sign(:serial => 2, :signer => ca)
  puts certificate.to_text


CRL
---

CRL の作成
::

  require 'zzz'
  include ZZZ::CA

  certificate = Certificate.new
  certificate.gen_private_key
  certificate.not_before = '2010/09/21 00:00:00'
  certificate.not_after = '2010/10/21 00:00:00'
  certificate.add_subject('C', 'JP')
  certificate.add_subject('ST', 'Tokyo')
  certificate.add_subject('L', 'Chuo')
  certificate.add_subject('O', 'O')
  certificate.add_subject('CN', 'CA')
  certificate.add_extension('basicConstraints', ['CA:TRUE', 'pathlen:0'], true)
  certificate.add_extension('keyUsage', ['keyCertSign', 'cRLSign'])
  certificate.add_extension('crlDistributionPoints', ['URI:http://example.com/example.crl'])
  certificate.add_extension('extendedKeyUsage',
                            ['TLS Web Server Authentication',
                            'TLS Web Client Authentication'])
  certificate.sign(:serial => 1)
  certificate.to_text

  crl = CRL.new
  crl.last_update = '2010/09/21 00:00:00'
  crl.next_update = '2010/10/21 00:00:00'
  crl.add_revoked(:serial => 1, :datetime => Time.now.to_s,
                                :reason => 'superseded')
  crl.add_revoked(:serial => 2, :datetime => Time.now.to_s)
  crl.add_revoked(:serial => 3, :datetime => Time.now.to_s,
                                :reason => 'cACompromise')

  crl.sign(:signer => certificate)
  puts crl.to_text


COPYRIGHT
=========

Copyright (c) 2011 Hiroshi Yoshida <hexa.diary@gmail.com>. See LICENSE for details.
