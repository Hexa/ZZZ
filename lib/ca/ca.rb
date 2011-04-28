#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

module CA
  X509_V1 = 0
  X509_V2 = 1
  X509_V3 = 2
  CSR_V1 = 0
  CSR_V2 = 1
  CRL_V1 = 0
  CRL_V2 = 1
end


module CA
  class X509

    attr_reader :private_key

    def initialize
    end

    def method_missing(name, *args)
      case name.to_s
      when /^.+=$/
        @x509.__send__(name, args[0])
      when /^.+$/
        @x509.__send__(name)
      end
    end

    def gen_private_key(params)
      @private_key = CA::Utils::gen_private_key(params)
    end

    def private_key=(private_key)
      @private_key = if private_key.instance_of(String)
                       CA::Utils::get_pkey_object(private_key)
                     else
                       private_key
                     end
    end

    def pkcs12
    end

  end
end

module CA
  class Certificate
    def initialize()
      super
    end

    def method_missing(name, *args)
      case name.to_s
      when /^(subject|issuer)=$/
        subject = CA::Utils::encode_subject(args[0])
        @x509.__send__(name, subject)
      when /^(not_(before|after)=$/
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
      CA::Utils::sign(:certificate, params)
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

module CA
  class Utils
    def self.sign(type, signer, params)
      data = params[:certificate] || params[:crl]
      serial = params[:serial] || DEFAULT_SERIAL

      case type
      when :certificate
        certificate_sign(signer, data, serial)
      when :request
        request_sign(signer)
      when :crl
        crl_sign(signer, data)
      else
        raise(Error, "Unexpected type: #{type}.")
      end
    end

    private
    def self.certificate_sign(signer, data, serial)
      data.serial = serial
      data.issuer = signer.subject
      data.certificate.sign(
        signer.private_key,
        OpenSSL::Digest.new(data.signature_algorithm))
      data.certificate
    end

    def self.crl_sign(signer, data)
      data.issuer = signer.subject
      data.crl.sign(
        signer.private_key,
        OpenSSL::Digest.new(data.signature_algorithm))
      data.crl
    end

    def self.request_sign(signer)
      signer.sign(
        signer.private_key,
        OpenSSL::Digest.new(signer.signature_algorithm))
      signer.request
    end

    def self.encode_extensions(extensions, certificates = {})
      extension_encoder = ExtensionEncoder.new
      extensions.each_pair do |oid, values|
        critical = values[:critical] || false
        extension_encoder.add(
          :oid => oid,
          :values => values[:values],
          :critical => critical)
      end
 
      certificates.each_pair.each do |key, certificate|
        extension_encoder.__send__("#{key}=".to_sym, certificate)
      end
      extension_encoder.encode
    end

    def self.get_pkey_object(private_key)
      case private_key
      when /^-----BEGIN RSA PRIVATE KEY-----/
        OpenSSL::PKey::RSA.new(private_key)
      when /^-----BEGIN DSA PRIVATE KEY-----/
        OpenSSL::PKey::DSA.new(private_key)
      end
    end

    def self.gen_x509_object(pem)
      case get_asn1_type(pem)
      when :certificate
        X509::Certificate.new(pem)
      when :request
        X509::Request.new(pem)
      when :crl
        X509::CRL.new(pem)
      end
    end

    def self.get_asn1_type(pem)
      case pem
      when /^-----BEGIN CERTIFICATE-----/
        :certificate
      when /^-----BEGIN CERTIFICATE REQUEST-----/
        :request
      when /^-----BEGIN X509 CRL-----/
        :crl
      else
        raise(Error, "Unexpected type: pem.")
      end
    end
  end
end
