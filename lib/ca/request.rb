#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

module CA
  class Request < X509

    def initialize
      super(:request)
    end

    def method_missing(name, *args)
      super
    end

    def request=(pem)
      @x509 = CA::Utils::gen_x509_object(pem)
    end

    def request
      @x509
    end

    def sign(params = {})
      signer = params[:signer] || self
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
