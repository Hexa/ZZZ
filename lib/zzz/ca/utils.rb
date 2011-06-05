#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require 'openssl'
require 'time'
require File.join(File.expand_path(File.dirname(__FILE__)), 'x509')
require File.join(File.expand_path(File.dirname(__FILE__)), 'subject_encoder')
require File.join(File.expand_path(File.dirname(__FILE__)), 'extension_encoder')
require File.join(File.expand_path(File.dirname(__FILE__)), 'error')

module ZZZ
  module CA
    class Utils
      ## デフォルトの公開鍵の鍵長
      DEFAULT_KEY_SIZE = 1024
      ## デフォルトの Exponent
      DEFAULT_PUBLIC_EXPONENT = 65567
      ## デフォルトの公開鍵のアルゴリズム
      DEFAULT_PUBLIC_KEY_ALGORITHM = PUBLIC_KEY_ALGORITHMS[:RSA]

      ## 秘密鍵／公開鍵の生成
      def self.gen_pkey(params)
        key_size = params[:key_size] || DEFAULT_KEY_SIZE
        exponent = params[:exponent] || DEFAULT_PUBLIC_EXPONENT
        public_key_algorithm = params[:public_key_algorithm] || DEFAULT_PUBLIC_KEY_ALGORITHM
        case public_key_algorithm
        when :RSA
          OpenSSL::PKey::RSA.new(key_size, exponent)
        when :DSA
          OpenSSL::PKey::DSA.new(key_size, exponent)
        else
          raise ZZZ::CA::Error
        end
      end

      ## OpenSSL::X509 オブジェクトの生成
      def self.new(type)
        case type
        when :certificate
          OpenSSL::X509::Certificate.new
        when :request
          OpenSSL::X509::Request.new
        when :crl
          OpenSSL::X509::CRL.new
        else
          raise ZZZ::CA::Error
        end
      end

      ## 日時のエンコード
      def self.encode_datetime(datetime)
        Time.parse(datetime)
      end

      ## Extensions のエンコード
      def self.encode_extensions(extensions, params = {})
        extension_encoder = ZZZ::CA::ExtensionEncoder.new
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

      ## DN のエンコード
      def self.encode_subject(subject)
        if subject.instance_of?(OpenSSL::X509::Name)
          subject
        else
          subject_encoder = ZZZ::CA::SubjectEncoder.new(subject)
          subject_encoder.encode
        end
      end

      ## OpenSSL::Cipher オブジェクトの生成
      def self.cipher(algorithm)
        OpenSSL::Cipher::Cipher.new(algorithm)
      end

      ## PEM 形式の秘密鍵からの OpenSSL::PKey オブジェクトの生成　
      def self.get_pkey_object(private_key)
        case private_key
        when /^-----BEGIN RSA PRIVATE KEY-----/
          OpenSSL::PKey::RSA.new(private_key)
        when /^-----BEGIN DSA PRIVATE KEY-----/
          OpenSSL::PKey::DSA.new(private_key)
        else
          raise ZZZ::CA::Error
        end
      end

      ## PEM からの OpenSSL::X509 オブジェクトの生成
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

      ## PEM からの証明書、CSR、CRL の判別
      def self.get_asn1_type(pem)
        case pem
        when /^-----BEGIN CERTIFICATE-----.+-----END CERTIFICATE-----$/m
          :certificate
        when /^-----BEGIN CERTIFICATE REQUEST-----.+-----END CERTIFICATE REQUEST-----$/m
          :request
        when /^-----BEGIN X509 CRL-----.+-----END X509 CRL-----$/m
          :crl
        else
          raise ZZZ::CA::Error
        end
      end

      ## 証明書の失効
      def self.revoked(serial, revoked_time)
        revoked = OpenSSL::X509::Revoked.new
        revoked.serial = serial
        revoked.time = ZZZ::CA::Utils::encode_datetime(revoked_time)
        revoked
      end
    end
  end
end
