===========
Certificate
===========

証明書を発行します．


Public Class Methods
====================

::new(pem = nil)
----------------

Certificate オブジェクトを生成します．

pem（証明書）が指定されている場合には，その証明書の Certificate オブジェクトを生成します．


Public Instance Methods
=======================

#not_before=(datetime)
----------------------

証明書が有効になる日時（not_before）を指定します．


#not_before=(datetime)
----------------------

証明書が無効になる日時（not_after）を指定します．


#certificate
------------

証明書（OpenSSL::X509::Certificate オブジェクト）を取得します．

#certificate=(pem_or_der)
-------------------------

発行済みの証明書から Certificate オブジェクトを生成します．

pem_or_der には PEM 形式，または，DER 形式の証明書を指定します．

#private_key=(private_key)
--------------------------

作成済みの秘密鍵を Certificate オブジェクトに指定します．

private_key には PEM または、OpenSSL::PKey オブジェクトを指定します．


#private_key
------------

秘密鍵を取得します．

取得できる秘密鍵は OpenSSL::PKey オブジェクトです．


#sign(params)
-------------

証明書に署名します．

params には :serial，:version，:signer をハッシュで指定することが可能です．

:serial には証明書のシリアルを指定します．指定がない場合，シリアルは 1 で証明書に署名されます．

:version には証明書のバージョンを指定します．指定がない場合，バージョンは X509v3 で証明書に署名されます．

:signer にはこの証明書に署名する主体の証明書と秘密鍵を持った Certificate オブジェクトを指定します．指定がない場合，自己署名します．
