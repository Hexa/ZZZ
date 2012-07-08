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
            raise ZZZ::CA::Error, "Unsupported public_key_algorithm: #{public_key_algorithm}"
          end
        end

        X509_CLASS_NAMES = {
          :certificate => 'Certificate',
          :request => 'Request',
          :crl => 'CRL'}

        ## OpenSSL::X509 オブジェクトの生成
        def new(type, pem = nil)
          case type
          when :certificate, :request, :crl
            pem ? gen_x509_with_args(type, pem) : gen_x509_without_args(type)
          else
            raise ZZZ::CA::Error, "Invalid type :#{type}"
          end
        end

        def gen_x509_with_args(type, pem)
          eval("OpenSSL::X509::#{X509_CLASS_NAMES[type]}.new(pem)")
        end

        def gen_x509_without_args(type)
          eval("OpenSSL::X509::#{X509_CLASS_NAMES[type]}.new")
        end

        ## 日時のエンコード
        def encode_datetime(datetime)
          Time.parse(datetime)
        end

        ## Extensions のエンコード
        def encode_extensions(extensions, params = {})
          extension_encoder = ZZZ::CA::ExtensionEncoder.new
          extensions.each do |oid, values|
            critical = values[:critical] || false
            extension_encoder.add(
              :oid => oid,
              :values => values[:values],
              :critical => critical,
              :type => values[:type])
          end

          certificates = params[:certificates] || {}
          certificates.each do |key, certificate|
            extension_encoder.__send__("#{key}=".to_sym, certificate)
          end

          extension_encoder.encode
        end

        ## OID の取得
        def get_oid_from_extension(extension)
          der = extension.to_der
          OpenSSL::X509::Extension.new(extension).oid
        end

        ## Value の取得
        def get_value_from_extension(extension)
          der = extension.to_der
          OpenSSL::X509::Extension.new(extension).value
        end

        ## DN のエンコード
        def encode_subject(subject)
          subject_encoder = ZZZ::CA::SubjectEncoder.new(subject)
          subject_encoder.encode
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
            raise ZZZ::CA::Error, "Unsupported private_key: #{private_key}"
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
            raise ZZZ::CA::Error, "Unsupported type: #{type}"
          end
        end

        ## TODO: 名前の変更
        def set_certificate(type, certificate)
          case certificate
          when OpenSSL::X509::Certificate, OpenSSL::X509::Request
            @certificates[type] = certificate
          else
            ## OpenSSL::X509 以外の場合
            case type
            when :issuer_certificate, :subject_certificate
              ZZZ::CA::Utils::x509_object(:certificate, certificate)
            when :subject_request
              ZZZ::CA::Utils::x509_object(:request, certificate)
            else
              raise ZZZ::CA::Error, "Invalid type: #{type}"
            end
          end
        end

        ## 証明書の失効
        def revoke_certificate(params)
          revoked = OpenSSL::X509::Revoked.new
          revoked.serial = params[:serial]
          revoked.time = ZZZ::CA::Utils::encode_datetime(params[:datetime])
          ZZZ::CA::Utils::set_reason(revoked, params[:reason])
          revoked
        end

        ## 失効理由を指定
        def set_reason(revoked, reason)
          if reason
            revoked_reason = ZZZ::CA::Utils::encode_extensions(
              'CRLReason' => {:values => [reason], :type => :enumerated})
            revoked.add_extension(revoked_reason)
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

        def get_digest(algorithm)
          OpenSSL::Digest.new(algorithm)
        end
      end
    end
  end
end
