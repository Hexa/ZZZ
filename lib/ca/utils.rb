#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

module CA
  require 'openssl'
  require 'time'

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

    def self.encode_datetime(datetime)
      Time.parse(datetime)
    end

    def self.encode_extensions(extensions, params = {})
      extension_encoder = CA::ExtensionEncoder.new
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

    def self.encode_subject(subject)
      if subject.instance_of?(OpenSSL::X509::Name)
        subject
      else
        subject_encoder = CA::SubjectEncoder.new(subject)
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
  end
end
