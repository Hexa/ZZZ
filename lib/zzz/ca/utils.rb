# -*- coding: utf-8 -*-

require 'openssl'
require 'time'
require 'zzz/ca/subject_encoder'
require 'zzz/ca/extension_encoder'
require 'zzz/ca/error'

module ZZZ
  module CA
    class Utils
      ## デフォルトの公開鍵の鍵長
      DEFAULT_KEY_SIZE = 1024
      ## デフォルトの Exponent
      DEFAULT_PUBLIC_EXPONENT = 65567
      ## デフォルトの公開鍵のアルゴリズム
      DEFAULT_PUBLIC_KEY_ALGORITHM = :RSA #PUBLIC_KEY_ALGORITHMS[:RSA]

      class << self
        ## 秘密鍵／公開鍵の生成
        def gen_pkey(params)
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
        def new(type, pem = nil)
          case type
          when :certificate
            pem.nil? ? OpenSSL::X509::Certificate.new : OpenSSL::X509::Certificate.new(pem)
          when :request
            pem.nil? ? OpenSSL::X509::Request.new : OpenSSL::X509::Request.new(pem)
          when :crl
            pem.nil? ? OpenSSL::X509::CRL.new : OpenSSL::X509::CRL.new(pem)
          else
            raise ZZZ::CA::Error
          end
        end
       
        ## 日時のエンコード
        def encode_datetime(datetime)
          Time.parse(datetime)
        end
       
        ## Extensions のエンコード
        def encode_extensions(extensions, params = {})
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
        def encode_subject(subject)
          ZZZ::CA::SubjectEncoder.new(subject).encode
        end
       
        ## OpenSSL::Cipher オブジェクトの生成
        def cipher(algorithm)
          OpenSSL::Cipher::Cipher.new(algorithm)
        end
       
        ## PEM 形式の秘密鍵からの OpenSSL::PKey オブジェクトの生成　
        def pkey_object(private_key)
          case private_key
          when /^-----BEGIN RSA PRIVATE KEY-----/
            OpenSSL::PKey::RSA.new(private_key)
          when /^-----BEGIN DSA PRIVATE KEY-----/
            OpenSSL::PKey::DSA.new(private_key)
          else
            raise ZZZ::CA::Error
          end
        end
       
        ## PEM または DER からの OpenSSL::X509 オブジェクトの生成
        def x509_object(type, pem_or_der)
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
        def verify_asn1(der)
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
end
