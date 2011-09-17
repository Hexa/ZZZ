=======
Request
=======

CSR を発行します．

Public Class Methods
====================

::new(pem = nil)
----------------

Request オブジェクトを生成します．

pem（CSR）が指定されている場合には，その CSR の Request オブジェクトを生成します．


Public Instance Methods
=======================

#request
--------

CSR（OpenSSL::X509::Request オブジェクト）を取得します．

#request=(pem_or_der)
---------------------

作成済みの CSR から Request オブジェクトを生成します．

pem_or_der には PEM 形式，または，DER 形式の CSR を指定します．

#private_key=(private_key)
--------------------------

作成済みの秘密鍵を Request オブジェクトに指定します．

private_key には PEM または、OpenSSL::PKey オブジェクトを指定します．

#sign(params)
-------------

証明書に署名します．

params には :version，:signer をハッシュで指定することが可能です．

:version には CSR のバージョンを指定します．指定がない場合，バージョンは 1 で証明書に署名されます．

:signer にはこの CSR に署名する主体の秘密鍵を持った Request オブジェクトを指定します．指定がない場合，自己署名します．
