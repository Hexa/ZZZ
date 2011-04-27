=======
CA (仮)
=======

:Author: Hexa
:Mail:  


妄想
====

RbCertificate と同じような感じで使用可能::

  certificate = Certificate.new
  certificate.gen_pkey
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

  crl = CRL.new
  crl.last_update = '2010/09/21 00:00:00'
  crl.next_update = '2010/10/21 00:00:00'

  certificate.sign(:crl => crl)
  crl.to_text

条件
====

- 重複は最小限まで減らす
- 共通処理は Utils Class へ
