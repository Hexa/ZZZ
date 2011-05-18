=======
Request
=======

:Authors: Hexa

CSR を発行します．

Methods
=======

class Request
-------------

::new
^^^^^

Request オブジェクトを生成します．

#request
^^^^^^^^

CSR（OpenSSL::X509::Request オブジェクト）を取得します．

#request=(pem)
^^^^^^^^^^^^^^

作成済みの CSR から Request オブジェクトを生成します．

pem には PEM 形式の CSR を指定します．

#private_key=(private_key)
^^^^^^^^^^^^^^^^^^^^^^^^^^

作成済みの秘密鍵を Request オブジェクトに指定します．

private_key には PEM または、OpenSSL::PKey オブジェクトを指定します．

#sign(params)
^^^^^^^^^^^^^

証明書に署名します．

params には :version，:signer をハッシュで指定することが可能です．

:version には CSR のバージョンを指定します．指定がない場合，バージョンは 1 で証明書に署名されます．

:signer にはこの CSR に署名する主体の秘密鍵を持った Request オブジェクトを指定します．指定がない場合，自己署名します．
