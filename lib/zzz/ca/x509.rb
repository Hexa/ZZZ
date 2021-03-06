# -*- coding: utf-8 -*-

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
      class << self
        ## Extension 等に使用する証明書の setter と getter の定義
        def ext_certificates_register(*names)
          names.each do |name|
            define_method(name) do
              @certificates[name]
            end

            define_method(:"#{name}=") do |args|
              @certificates[name] = ZZZ::CA::Utils::set_certificate(name, args)
            end
          end
        end
      end

      ## 証明書や CRL に署名するためのデフォルトのアルゴリズム
      DEFAULT_SIGNATURE_ALGIRITHM = ZZZ::CA::SIGNATURE_ALGORITHMS[:SHA1]

      attr_writer :signature_algorithm
      ext_certificates_register :issuer_certificate, :subject_certificate, :subject_request

      ## 引数 type には生成するインスタンスを指定
      def initialize(type, pem = nil)
        @certificates = {}
        @extensions = {}
        @subject = []
        @x509 = ZZZ::CA::Utils::new(type, pem)
      end

      def method_missing(name, *args)
        @x509.__send__(name, *args)
      end

      ## subject の指定
      def add_subject(oid, value)
        @subject << {oid => value}
        @x509.subject = ZZZ::CA::Utils::encode_subject(@subject)
      end

      ## 秘密鍵／公開鍵の生成
      def gen_private_key(params = {})
        @private_key = ZZZ::CA::Utils::gen_pkey(params)
        @x509.public_key = @private_key
        @private_key
      end

      ## 秘密鍵の暗号化
      def encrypted_private_key(params)
        algorithm = params[:algorithm]
        passphrase = params[:passphrase]
        @private_key.export(ZZZ::CA::Utils::cipher(algorithm), passphrase)
      end

      ## 署名アルゴリズムの取得
      def signature_algorithm
        # Certificate#signature_algorithm == 'itu-t' は署名前
        case @x509.signature_algorithm
        when 'itu-t'
          @signature_algorithm
        else
          method_missing(:signature_algorithm)
        end
      end

      ## Extension の指定
      def extensions=(extensions, params = {})
        @extensions = extensions
        extensions.each do |oid, values|
          add_extension(oid, values[:values], values[:critical] || false, params)
        end
      end

      ## Extension の指定
      def add_extension(oid, values, critical = false, params ={})
        extension = {oid => {:values => values, :critical => critical}}
        @extensions.merge!(extension)
      end

      def encode_extensions(params ={})
        @certificates[:subject_certificate] ||= self.to_pem if @certificates.include?(:subject_certificate) and (self.class == ZZZ::CA::Certificate)
        params[:certificates] = @certificates
        @x509.extensions = ZZZ::CA::Utils::encode_extensions(@extensions, params)
      end

      ## 証明書への署名
      def sign(type, signer = self, params = {})
        case type
        when :certificate
          self.encode_extensions
          self.serial = params[:serial]
          self.issuer = signer.subject
        when :request
        when :crl
          self.encode_extensions
          self.issuer = signer.subject
        else
          raise ZZZ::CA::Error
        end
        self.version = params[:version]
        _sign(type, signer)
      end

      private
      def _sign(type, signer) # :nodoc:
        digest = ZZZ::CA::Utils::get_digest(self.signature_algorithm || DEFAULT_SIGNATURE_ALGIRITHM)
        x509 = self.__send__(type)
        x509.sign(signer.private_key, digest)
        self
      end
    end
  end
end
