#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require File.join(File.expand_path(File.dirname(__FILE__), 'x509'))

module ZZZ
  module CA
    class CRL < X509
      ## デフォルトの CRL のバージョン
      DEFAULT_VERSION = VERSIONS[:CRLv2]

      def initialize
        super(:crl)
      end

      def method_missing(name, *args)
        case name.to_s
        when /^(last|next)_update=$/
          datetime = CA::Utils::encode_datetime(args[0])
          @x509.__send__(name, datetime)
        else
          super
        end
      end

      ## PEM 形式の CRL の指定
      ## TODO: DER の指定
      def crl=(pem)
        @x509 = CA::Utils::gen_x509_object(pem)
      end

      ## CRL (OpenSSL::X509::CRL オブジェクト) の取得
      def crl
        @x509
      end

      ## 失効させる証明書 (シリアル) の指定
      def add_revoked(params)
        serial = params[:serial]
        revoked_time = params[:datetime]
        revoked = OpenSSL::X509::Revoked.new
        revoked.serial = serial
        revoked.time = ZZZ::CA::Utils::encode_datetime(revoked_time)
        @x509.add_revoked(revoked)
      end

      ## CRL への署名
      def sign(params)
        params[:data] = self
        signer = params[:signer]
        params[:version] ||= DEFAULT_VERSION
        super(:crl, signer, params)
      end
    end
  end
end
