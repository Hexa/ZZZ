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
          type = values[:type]
          extension_encoder.add(
            :oid => oid,
            :values => values[:values],
            :critical => critical,
            :type => type)
        end

        certificates = params[:certificates] || {}
        certificates.each_pair.each do |key, certificate|
          extension_encoder.__send__("#{key}=".to_sym, certificate)
        end

        extension_encoder.encode
      end

      ## DN のエンコード
      def self.encode_subject(subject)
        subject.instance_of?(OpenSSL::X509::Name) ? subject : ZZZ::CA::Utils::encode(subject)
      end

      def self.encode(subject)
        subject_encoder = ZZZ::CA::SubjectEncoder.new(subject)
        subject_encoder.encode
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

      ## PEM からの証明書、CSR、CRL の判別
      def self.asn1_type(pem)
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

      ## PEM からの OpenSSL::X509 オブジェクトの生成
      def self.x509_object(type, pem_or_der)
        case type
        when :certificate
          OpenSSL::X509::Certificate.new(pem_or_der)
        when :request
          OpenSSL::X509::Request.new(pem_or_der)
        when :crl
          OpenSSL::X509::CRL.new(pem_or_der)
        else
          raise ZZZ::CA::Error, "#{__LINE__}: Unsupported type: #{type}"
        end
      end

      ## str が ASN1 であるかの確認
      def self.verify_asn1(der)
        begin
          OpenSSL::ASN1.decode_all(der)
          true
        rescue
          false
        end
      end
    end
  end
end
