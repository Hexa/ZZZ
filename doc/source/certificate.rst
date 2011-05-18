===========
Certificate
===========

:Authors: Hexa

証明書を発行します．

Methods
=======

class Certificate
-----------------

::new
^^^^^

Certificate オブジェクトを生成します．

#certificate
^^^^^^^^^^^^

証明書（OpenSSL::X509::Certificate オブジェクト）を取得します．

#certificate=(pem)
^^^^^^^^^^^^^^^^^^

発行済みの証明書から Certificate オブジェクトを生成します．

pem には PEM 形式の証明書を指定します．

#private_key=(private_key)
^^^^^^^^^^^^^^^^^^^^^^^^^^

作成済みの秘密鍵を Certificate オブジェクトに指定します．

private_key には PEM または、OpenSSL::PKey オブジェクトを指定します．

#sign(params)
^^^^^^^^^^^^^

証明書に署名します．

params には :serial，:version，:signer をハッシュで指定することが可能です．

:serial には証明書のシリアルを指定します．指定がない場合，シリアルは 1 で証明書に署名されます．

:version には証明書のバージョンを指定します．指定がない場合，バージョンは X509v3 で証明書に署名されます．

:signer にはこの証明書に署名する主体の証明書と秘密鍵を持った Certificate オブジェクトを指定します．指定がない場合，自己署名します．
