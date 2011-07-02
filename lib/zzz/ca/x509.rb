# -*- coding: utf-8 -*-

require File.join(File.expand_path(File.dirname(__FILE__)), 'utils')

module ZZZ
  module CA
    VERSIONS ||= {}
    VERSIONS[:X509v1] ||= 0
    VERSIONS[:X509v2] ||= 1
    VERSIONS[:X509v3] ||= 2
    VERSIONS[:REQUESTv1] ||= 0
    VERSIONS[:REQUESTv2] ||= 1
    VERSIONS[:CRLv1] ||= 0
    VERSIONS[:CRLv2] ||= 1

    SIGNATURE_ALGORITHMS ||= {}
    SIGNATURE_ALGORITHMS[:SHA1] ||= "SHA1"
    SIGNATURE_ALGORITHMS[:MD5] ||= "MD5"

    PUBLIC_KEY_ALGORITHMS ||= {}
    PUBLIC_KEY_ALGORITHMS[:RSA] ||= :RSA
    PUBLIC_KEY_ALGORITHMS[:DSA] ||= :DSA

    class X509
      ## 証明書や CRL に署名するためのデフォルトのアルゴリズム
      DEFAULT_SIGNATURE_ALGIRITHM = ZZZ::CA::SIGNATURE_ALGORITHMS[:SHA1]

      ## 秘密鍵
      attr_reader :private_key
      attr_writer :signature_algorithm

      ## 引数 type には生成するインスタンスを指定
      ## * 証明書:  :certificate
      ## * CSR:     :request
      ## * CRL:     :crl
      def initialize(type)
        @certificates = {}
        @extensions = {}
        @x509 = CA::Utils::new(type)
      end

      def method_missing(name, *args)
        case name.to_s
        when /^(subject|issuer)=$/
          subject = CA::Utils::encode_subject(args[0])
          @x509.__send__(name, subject)
        when /^.+=$/
          @x509.__send__(name, args[0])
        when /^.+$/
          @x509.__send__(name)
        end
      end

      ## 秘密鍵／公開鍵の生成
      def gen_private_key(params = {})
        @private_key = CA::Utils::gen_pkey(params)
        @x509.public_key = @private_key
        @private_key
      end

      ## 秘密鍵の暗号化
      def encrypted_private_key(params)
        algorithm = params[:algorithm]
        passphrase = params[:passphrase]
        @private_key.export(CA::Utils::cipher(algorithm), passphrase)
      end

      ## 署名アルゴリズムの取得
      def signature_algorithm
        # Certificate#signature_algorithm == 'itu-t' は署名前
        case @x509.signature_algorithm
        when 'itu-t'
          @signature_algorithm
        else
          method_missing(:signature_algorithm, [])
        end
      end

      ## 証明書や CRL の Extensions で使用する、この証明書の発行者の証明書の指定
      def issuer_certificate=(certificate)
        @certificates[:issuer_certificate] = CA::Utils::x509_object(:certificate, certificate)
      end

      ## 証明書や CRL の Extensions で使用する、この証明書の発行者の証明書取得
      def issuer_certificate
        @certificates[:issuer_certificate]
      end

      ## この証明書の発行元になる CSR の指定
      def subject_request=(request)
        @certificates[:subject_request] = CA::Utils::x509_object(:request, request)
      end

      ## この証明書の発行元になる CSR の取得
      def subject_request
        @certificates[:subject_request]
      end

      ## Extension の指定
      def extensions=(extensions, params = {})
        params[:certificates] = @certificates
        @extensions = extensions
        @x509.extensions = CA::Utils::encode_extensions(@extensions, params)
      end

      ## Extension の指定
      def add_extension(oid, values, critical = false, params ={})
        params[:certificates] = @certificates
        extension = {}
        extension[oid] = {:values => values, :critical => critical}
        @extensions.merge!(extension)
        @x509.extensions = CA::Utils::encode_extensions(@extensions, params)
      end

      ## 証明書への署名
      def sign(type, signer, params = {})
        case type
        when :certificate
          data = params[:certificate] || self
          data.version = params[:version]
          serial = params[:serial]
          certificate_sign(signer, data, serial)
        when :request
          signer.version = params[:version]
          request_sign(signer)
        when :crl
          data = params[:crl] || self
          data.version = params[:version]
          crl_sign(signer, data)
        else
          raise ZZZ::CA::Error
        end
      end

      private
      def certificate_sign(signer, data, serial)
        data.serial = serial
        data.issuer = signer.subject
        signature_algorithm = data.signature_algorithm || DEFAULT_SIGNATURE_ALGIRITHM
        data.certificate.sign(
          signer.private_key,
          OpenSSL::Digest.new(signature_algorithm))
        data
      end

      def crl_sign(signer, data)
        data.issuer = signer.subject
        signature_algorithm = data.signature_algorithm || DEFAULT_SIGNATURE_ALGIRITHM
        data.crl.sign(
          signer.private_key,
          OpenSSL::Digest.new(signature_algorithm))
        data
      end

      def request_sign(signer)
        signature_algorithm = signer.signature_algorithm || DEFAULT_SIGNATURE_ALGIRITHM
        signer.request.sign(
          signer.private_key,
          OpenSSL::Digest.new(signature_algorithm))
          signer
      end
    end
  end
end
