===
CRL
===

CRL を発行します．

Public Class Methods
====================

::new(pem = nil)
----------------

CRL オブジェクトを生成します．

pem（CRL）が指定されている場合には，その CRL の CRL オブジェクトを生成します．


Public Instance Methods
=======================

#last_update=(datetime)
-----------------------

この CRL の発行日時（last_update）を指定します．


#next_update=(datetime)
-----------------------

次の CRL の発行日時（next_update）を指定します．


#add_revoked(params)
--------------------

失効させる証明書を指定します．

params には :serial と :datetime を指定します．

:serial には失効させる証明書のシリアルを指定します．

:datetime には証明書を失効させる日時を指定します．


#crl
----

CRL (OpenSSL::X509::CRL オブジェクト) を取得します．

#crl=(pem_or_der)
-----------------

発行済みの CRL から CRL オブジェクトを生成します．

pem_or_der には PEM 形式，または，DER 形式の CRL を指定します．

#sign(parrams)
--------------

CRL に署名します．

params には :signer をハッシュで指定します．また，:version を指定することが可能です．

:signer には CRL に署名する主体の証明書と秘密鍵を持った Certificate オブジェクトを指定します．

:version には CRL のバージョンを指定します．指定がない場合は，バージョン 2 で署名します．
