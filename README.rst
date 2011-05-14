========
ZZZ (仮)
========

:Author: Hexa
:Mail:  hexa.diary@gmail.com


目的
====

RbCertificate の設計では，証明書も CSR も CRL も同じように扱っていたため，
変更しにくくなっている箇所があるので，同じような使い方ができるけれども，
それぞれの役割を分けた設計にしてみる

CSR::

  require './lib/zzz/ca'
  include ZZZ::CA

  request = Request.new
  request.gen_private_key
  subject = [
    {'C' => 'JP'},
    {'ST' => 'Tokyo'},
    {'L' => 'Chuo'},
    {'O' => 'O'},
    {'CN' => 'Server'}]
  request.subject = subject
  request.sign
  request.to_text

Certificate::

  require './lib/zzz/ca'
  include ZZZ::CA
  certificate = Certificate.new
  certificate.gen_private_key
  certificate.not_before = '2010/09/21 00:00:00'
  certificate.not_after = '2010/10/21 00:00:00'
  subject = [
    {'C' => 'JP'},
    {'ST' => 'Tokyo'},
    {'L' => 'Chuo'},
    {'O' => 'O'},
    {'CN' => 'CA'}]
  certificate.subject = subject
  extensions = {
    'basicConstraints' => {
      :values => ['CA:TRUE', 'pathlen:0']},
    'keyUsage' => {
      :values => ['keyCertSign', 'cRLSign']},
    'extendedKeyUsage' => {
      :values => [
        'TLS Web Server Authentication',
        'TLS Web Client Authentication']}}
  certificate.extensions = extensions
  certificate.sign(:serial => 1)

CRL::

  require './lib/zzz/ca'
  include ZZZ::CA
  crl = CRL.new
  crl.last_update = '2010/09/21 00:00:00'
  crl.next_update = '2010/10/21 00:00:00'
  crl.add_revoked(:serial => 1, :datetime => Time.now.to_s)
  crl.add_revoked(:serial => 2, :datetime => Time.now.to_s)

  crl.sign(:signer => certificate)
  crl.to_text


条件
====

- 各クラスごとの役割は分ける
- 重複は最小にする
- 共通処理は Utils クラスへ
- CA 以外も実装できるようにしておく
