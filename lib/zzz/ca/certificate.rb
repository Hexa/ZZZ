# -*- coding: utf-8 -*-

#
# 証明書を発行するクラスライブラリ
#
require 'zzz/ca/x509'

module ZZZ
  module CA
    class CertificateError < RuntimeError; end
  end
end

module ZZZ
  module CA
    class Certificate < X509
      ## デフォルトの証明書発行時のシリアル番号
      DEFAULT_SERIAL = 1
      ## デフォルトの証明書のバージョン（X509v3）
      DEFAULT_VERSION = VERSIONS[:X509v3]

      class << self
        ## ZZZ::CA::Request から ZZZ::CA::Certificate への移行
        def set_request(request)
          certificate = ZZZ::CA::Certificate.new
          certificate.private_key = request.private_key
          certificate.public_key = request.public_key
          certificate.subject = request.subject
          certificate.subject_request = request.to_pem
          extensions = find_extensions(request)
          certificate.extensions = extensions unless extensions.empty?
          certificate
        end

        def find_extensions(request)
          extension_request = find_ext_request(request)
          extension_request.map do |extension|
            extensions = {}
            oid = ZZZ::CA::Utils.get_oid_from_extension(extension)
            value = ZZZ::CA::Utils.get_value_from_extension(extension)
            extensions[oid] ||= {}
            extensions[oid][:values] ||= []
            extensions[oid][:values] << value
            extensions
          end
        end

        ## CSR の Attributes から Ext を取得
        def find_ext_request(request)
          attributes =  request.attributes
          attribute = attributes.find {|attribute| attribute.oid == 'extReq' }

          attribute ? attribute.value.value[0] : []
        end

        ## PKCS#12 形式の証明書に変換
        def pkcs12(passphrase, certificate, private_key, name = '')
          case certificate
          when OpenSSL::X509::Certificate
            OpenSSL::PKCS12.create(passphrase, name, private_key, certificate)
          when ZZZ::CA::Certificate
            OpenSSL::PKCS12.create(passphrase, name, private_key, certificate.certificate)
          else
            raise ZZZ::CA::CertificateError, "Invalid certificate: #{certificate}"
          end
        end
      end

      def initialize(pem = nil)
        super(:certificate, pem)
      end

      def method_missing(name, *args)
        case name
        when :not_before=, :not_after=
          datetime = case args[0]
                     when String
                       ZZZ::CA::Utils::encode_datetime(args[0])
                     when Time
                       args[0]
                     else
                       raise ZZZ::CA::CertificateError, "Invalid datetime: #{datetime}"
                     end
          @x509.__send__(name, datetime)
        when :private_key, :pkey
          @private_key
        when :verify
          @x509.__send__(name, args[0])
        else
          super
        end
      end

      ## 秘密鍵の指定
      def private_key=(private_key)
        @private_key = case private_key
                       when String
                         ZZZ::CA::Utils::pkey_object(private_key)
                       when OpenSSL::PKey::RSA, OpenSSL::PKey::DSA
                         private_key
                       else
                         raise ZZZ::CA::CertificateError, "Invalid private_key: #{private_key}"
                       end
      end

      ## 証明書への署名
      def sign(params)
        signer = params[:signer] || self
        params[:data] ||= self
        params[:serial] ||= DEFAULT_SERIAL
        params[:version] ||= DEFAULT_VERSION
        super(:certificate, signer, params)
      end

      ## 証明書を指定
      def certificate=(pem_or_der)
        @x509 = CA::Utils::x509_object(:certificate, pem_or_der)
      end

      ## 証明書（OpenSSL::X509::Certificate オブジェクト）の取得
      def certificate
        @x509
      end

      ## PKCS#12 形式の証明書を取得
      def pkcs12(passphrase, name = '')
        OpenSSL::PKCS12.create(passphrase, name, @private_key, @x509)
      end
    end
  end
end
