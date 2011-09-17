# -*- coding: utf-8 -*-

require File.join(File.expand_path(File.dirname(__FILE__), 'x509'))

## TODO:: ca 以下でよいか

module ZZZ
  module CA
    class Request < X509
      ## デフォルトの CSR のバージョン
      DEFAULT_VERSION = ZZZ::CA::VERSIONS[:REQUESTv2]

      def initialize(pem = nil)
        super(:request, pem)
      end

      def method_missing(name, *args)
        case name
        when :private_key, :pkey
          @private_key
        else
          super
        end
      end

      ## 秘密鍵の指定
      def private_key=(private_key)
        @private_key = case "#{private_key.class}"
                       when 'String'
                         CA::Utils::get_pkey_object(private_key)
                       when 'OpenSSL::PKey::RSA', 'OpenSSL::PKey::DSA'
                         private_key
                       else
                         raise ZZZ::CA::Error
                       end
      end

      ## PEM 形式の CSR の指定
      def request=(pem_or_der)
        @x509 = CA::Utils::x509_object(:request, pem_or_der)
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
    end
  end
end
