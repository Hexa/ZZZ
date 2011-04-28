#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

module CA
  class Utils
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
  end
end
