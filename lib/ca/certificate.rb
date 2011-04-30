#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

module CA
  class Certificate < X509

    DEFAULT_SERIAL = 1

    def initialize
      super(:certificate)
    end

    def method_missing(name, *args)
      case name.to_s
      when /^(subject|issuer)=$/
        subject = CA::Utils::encode_subject(args[0])
        @x509.__send__(name, subject)
      when /^(not_(before|after))=$/
        datetime = CA::Utils::encode_datetime(args[0])
        @x509.__send__(name, datetime)
      when /^(private_key)|(pkey)$/
        @private_key
      when /^.+=$/
        @x509.__send__(name, args[0])
      when /^.+$/
        @x509.__send__(name)
      end
    end

    def sign(params)
      signer = params[:signer] || self
      params[:data] ||= self
      params[:serial] ||= DEFAULT_SERIAL
      super(:certificate, signer, params)
    end

    def certificate=(pem)
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
