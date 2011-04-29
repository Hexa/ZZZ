#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

module CA
  require 'openssl'

  class Utils
    DEFAULT_KEY_SIZE = 1024
    DEFAULT_PUBLIC_EXPONENT = 65567
    DEFAULT_PUBLIC_KEY_ALGORITHM = :RSA

    def self.gen_pkey(params)
      key_size = params[:key_size] || DEFAULT_KEY_SIZE
      exponent = params[:exponent] || DEFAULT_PUBLIC_EXPONENT
      public_key_algorithm = params[:public_key_algorithm] || DEFAULT_PUBLIC_KEY_ALGORITHM

      case public_key_algorithm
      when :RSA
        OpenSSL::PKey::RSA.new(key_size, exponent)
      when :DSA
        OpenSSL::PKey::DSA.new(key_size, exponent)
      end
    end

    def self.new(type)
      case type
      when :certificate
        OpenSSL::X509::Certificate.new
      when :request
        OpenSSL::X509::Request.new
      when :crl
        OpenSSL::X509::CRL.new
      end
    end

    def self.encode_extensions(extensions, params = {:certificates => {}})
      extension_encoder = ExtensionEncoder.new
      extensions.each_pair do |oid, values|
        critical = values[:critical] || false
        extension_encoder.add(
          :oid => oid,
          :values => values[:values],
          :critical => critical)
      end

      certificates = params[:certificates]
      certificates.each_pair.each do |key, certificate|
        extension_encoder.__send__("#{key}=".to_sym, certificate)
      end

      extension_encoder.encode
    end

    def self.encode_subject(subjcet)
      if subject.instance_of?(OpenSSL::X509::Name)
        subject
      else
        subject_encoder = SubjectEncoder.new(subject)
        subject_encoder.encode
      end
    end

    def self.cipher(algorithm)
      OpenSSL::Cipher::Cipher.new(algorithm)
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
        OpenSSL::X509::Certificate.new(pem)
      when :request
        OpenSSL::X509::Request.new(pem)
      when :crl
        OpenSSL::X509::CRL.new(pem)
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

    def self.sign(type, signer, params)
      data = params[:certificate] || params[:crl]
      serial = params[:serial]

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
  end
end
