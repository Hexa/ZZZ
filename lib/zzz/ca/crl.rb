# -*- coding: utf-8 -*-

require 'zzz/ca/x509'

module ZZZ
  module CA
    class CRLError < RuntimeError; end
  end
end

module ZZZ
  module CA
    class CRL < X509
      ## デフォルトの CRL のバージョン
      DEFAULT_VERSION = VERSIONS[:CRLv2]

      def initialize(pem = nil)
        super(:crl, pem)
      end

      def method_missing(name, *args)
        case name
        when :last_update=, :next_update=
          datetime = case args[0]
                     when String
                       ZZZ::CA::Utils::encode_datetime(args[0])
                     when Time
                       args[0]
                     else
                       raise ZZZ::CA::CRLError
                     end
          @x509.__send__(name, datetime)
        else
          super
        end
      end

      ## PEM 形式の CRL の指定
      def crl=(pem_or_der)
        @x509 = ZZZ::CA::Utils::x509_object(:crl, pem_or_der)
      end

      ## CRL (OpenSSL::X509::CRL オブジェクト) の取得
      def crl
        @x509
      end

      ## 失効させる証明書 (シリアル) の指定
      def add_revoked(params)
        revoked = revoke(params)
        @x509.add_revoked(revoked)
      end

      ## CRL への署名
      def sign(params)
        params[:data] = self
        signer = params[:signer]
        params[:version] ||= DEFAULT_VERSION
        super(:crl, signer, params)
      end

      private
      def revoke(params)
        ZZZ::CA::Utils::revoke_certificate(params)
      end
    end
  end
end
