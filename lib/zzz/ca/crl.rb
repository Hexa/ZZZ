# -*- coding: utf-8 -*-

require File.join(File.expand_path(File.dirname(__FILE__), 'x509'))

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
          datetime = CA::Utils::encode_datetime(args[0])
          @x509.__send__(name, datetime)
        else
          super
        end
      end

      ## PEM 形式の CRL の指定
      def crl=(pem_or_der)
        @x509 = CA::Utils::x509_object(:crl, pem_or_der)
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

      def revoke(params)
        serial = params[:serial]
        revoked_time = params[:datetime]
        revoked = OpenSSL::X509::Revoked.new
        revoked.serial = serial
        revoked.time = ZZZ::CA::Utils::encode_datetime(revoked_time)
        unless params[:reason].nil?
          reason = params[:reason]
          revoked_reason = CA::Utils::encode_extensions(
            'CRLReason' => {:values => [reason], :type => :enumerated})
          revoked.add_extension(revoked_reason)
        end
        revoked
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
