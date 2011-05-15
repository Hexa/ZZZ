#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require File.join(File.expand_path(File.dirname(__FILE__), 'x509'))

module ZZZ
  module CA
    class Request < X509

      ## デフォルトの CSR のバージョン
      DEFAULT_VERSION = VERSIONS[:REQUESTv2]

      def initialize
        super(:request)
      end

      def method_missing(name, *args)
        case name.to_s
        when /^(private_key)|(pkey)$/
          @private_key
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

      ## PEM 形式の CSR の指定
      def request=(pem)
        @x509 = CA::Utils::gen_x509_object(pem)
      end

      ## CSR (OpenSSL::X509::Request オブジェクト) の取得
      def request
        @x509
      end

      ## CSR への署名
      def sign(params = {})
        signer = params[:signer] || self
        params[:version] ||= DEFAULT_VERSION
        super(:request, signer, params)
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
