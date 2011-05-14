#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

module ZZZ
  module CA
    class CRL < X509
      DEFAULT_VERSION = 2

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

      def crl=(pem)
        @x509 = CA::Utils::gen_x509_object(pem)
      end

      def crl
        @x509
      end

      def add_revoked(params)
        serial = params[:serial]
        revoked_time = params[:datetime]
        revoked = CA::Utils::revoked(serial, revoked_time)
        @x509.add_revoked(revoked)
      end

      def sign(params)
        params[:data] = self
        signer = params[:signer]
        params[:version] ||= DEFAULT_VERSION
        super(:crl, signer, params)
      end
    end
  end
end
