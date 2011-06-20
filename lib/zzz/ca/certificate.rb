# -*- coding: utf-8 -*-

require File.join(File.expand_path(File.dirname(__FILE__)), 'utils')

module ZZZ
  module CA
    class Certificate < X509

      ## デフォルトの証明書発行時のシリアル番号
      DEFAULT_SERIAL = 1
      ## デフォルトの証明書のバージョン（X509v3）
      DEFAULT_VERSION = VERSIONS[:X509v3]

      def initialize
        super(:certificate)
      end

      def method_missing(name, *args)
        case name.to_s
        when /^not_(before|after)=$/
          datetime = CA::Utils::encode_datetime(args[0])
          @x509.__send__(name, datetime)
        when /^(private_key)|(pkey)$/
          @private_key
        when /^verify$/
          @x509.__send__(name, args[0])
        else
          super
        end
      end

      ## 秘密鍵の指定
      def private_key=(private_key)
        @private_key = if private_key.instance_of?(String)
                         CA::Utils::get_pkey_object(private_key)
                       else
                         private_key
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
        case CA::Utils::verify_asn1(pem_or_der)
        when true
          @x509 = CA::Utils::gen_x509_object_from_der(self.class, pem_or_der)
        when false
          @x509 = CA::Utils::gen_x509_object(pem_or_der)
        end
      end

      ## 証明書（OpenSSL::X509::Certificate オブジェクト）の取得
      def certificate
        @x509
      end
    end
  end
end
