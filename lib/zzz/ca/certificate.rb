#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require File.join(File.expand_path(File.dirname(__FILE__), 'x509'))

module ZZZ
  module CA
    class Certificate < X509

      ## デフォルトの証明書発行時のシリアル番号
      DEFAULT_SERIAL = 1
      ## デフォルトの証明書のバージョン（X509v3）
      DEFAULT_VERSION = 2

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
        else
          super
        end
      end

      ## 秘密鍵の指定
      ## 引数: private_key には PEM または、OpenSSL::PKey オブジェクトを指定
      ##       文字列の場合は PEM として処理
      ##       文字列の以外の場合は PEM として処理
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

      ## PEM 形式の証明書を指定
      def certificate=(pem)
        @x509 = CA::Utils::gen_x509_object(pem)
      end

      ## 証明書（OpenSSL::X509::Certificate オブジェクト）の取得
      def certificate
        @x509
      end

      ## 署名アルゴリズムの取得
      def signature_algorithm
        case @x509.signature_algorithm
        when 'itu-t'
          @signature_algorithm
        else
          @x509.signature_algorithm
        end
      end
    end
  end
end
