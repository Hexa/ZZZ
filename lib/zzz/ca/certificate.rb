# -*- coding: utf-8 -*-

require 'zzz/ca/x509'

module ZZZ
  module CA
    class Certificate < X509

      ## デフォルトの証明書発行時のシリアル番号
      DEFAULT_SERIAL = 1
      ## デフォルトの証明書のバージョン（X509v3）
      DEFAULT_VERSION = VERSIONS[:X509v3]

      class << self
        ## ZZZ::CA::Request から ZZZ::CA::Certificate への移行
        def set_request(signed_request)
          certificate = Certificate.new
          certificate.private_key = signed_request.private_key
          certificate.public_key = signed_request.public_key
          certificate.subject = signed_request.subject
          certificate.subject_request = signed_request.to_pem
          ## TODO: Attribute を Extension へ
          certificate
        end
      end

      def initialize(pem = nil)
        super(:certificate, pem)
      end

      def method_missing(name, *args)
        case name
        when :not_before=, :not_after=
          datetime = CA::Utils::encode_datetime(args[0])
          @x509.__send__(name, datetime)
        when :private_key, :pkey
          @private_key
        when :verify
          @x509.__send__(name, args[0])
        else
          super
        end
      end

      ## 秘密鍵の指定
      def private_key=(private_key)
        ## TODO: 書き直す
        @private_key = case private_key
                       when String
                         CA::Utils::pkey_object(private_key)
                       when OpenSSL::PKey::RSA, OpenSSL::PKey::DSA
                         private_key
                       else
                         raise ZZZ::CA::Error
                       end
      end

      ## 証明書への署名
      def sign(params)
        signer = params[:signer] || self
        params[:data] ||= self
        params[:serial] ||= DEFAULT_SERIAL
        params[:version] ||= DEFAULT_VERSION
        super(:certificate, signer, params)
      end

      ## 証明書を指定
      def certificate=(pem_or_der)
        @x509 = CA::Utils::x509_object(:certificate, pem_or_der)
      end

      ## 証明書（OpenSSL::X509::Certificate オブジェクト）の取得
      def certificate
        @x509
      end

      ## PKCS#12 形式の証明書を取得
      def pkcs12(passphrase, name = '')
        OpenSSL::PKCS12.create(passphrase, name, @private_key, @x509)
      end

      class << self
        ## PKCS#12 形式の証明書に変換
        ## TODO: certificate は必須？
        def pkcs12(private_key, certificate, passphrase, name = '')
          OpenSSL::PKCS12.create(passphrase, name, private_key, certificate)
        end
      end
    end
  end
end
