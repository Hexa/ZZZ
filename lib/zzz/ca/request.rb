#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

module ZZZ
  module CA
    class Request < X509

      DEFAULT_VERSION = 1

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

      def private_key=(private_key)
        @private_key = if private_key.instance_of?(String)
                         CA::Utils::get_pkey_object(private_key)
                       else
                         private_key
                       end
      end

      def request=(pem)
        @x509 = CA::Utils::gen_x509_object(pem)
      end

      def request
        @x509
      end

      def sign(params = {})
        signer = params[:signer] || self
        params[:version] ||= DEFAULT_VERSION
        super(:request, signer, params)
      end

      def request=(pem)
        @x509 = CA::Utils::gen_x509_object(pem)
      end

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
