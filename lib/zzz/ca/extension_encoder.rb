# -*- coding: utf-8 -*-

require 'openssl'
require 'zzz/ca/error'

module ZZZ
  module CA
    class ExtensionEncoder
      attr_reader :encoded_extensions

      def initialize(extensions = {})
        @extensions = extensions
        @encoded_extensions = []
        @extension_factory = OpenSSL::X509::ExtensionFactory.new
      end

      def method_missing(name, *args)
        case name
        when :subject_request
          @extension_factory.subject_request
        when :subject_request=
          request = args[0]
          subject_request = case request
                            when String
                              OpenSSL::X509::Request.new(request)
                            when OpenSSL::X509::Request
                              request
                            else
                              raise ZZZ::CA::Error
                            end
          @extension_factory.__send__(name, subject_request)
        when :subject_certificate=, :issuer_certificate=
          cert = args[0]
          certificate = case cert
                        when String
                          OpenSSL::X509::Certificate.new(cert)
                        when OpenSSL::X509::Certificate
                          cert
                        else
                          raise ZZZ::CA::Error
                        end
          @extension_factory.__send__(name, certificate)
        else
          @extension_factory.__send__(name, *args)
        end
      end

      ## 現在指定してある Extension の一覧の取得
      def show
        @extensions
      end

      ## Extension の追加
      def add(params)
        oid = params[:oid]
        values = params[:values]
        critical = params[:critical] || false
        type = params[:type] || :default
        @extensions[oid] ||= {}
        unless type == :default
          @extensions[oid].merge!(:values => values, :critical => critical, :type => type)
        else
          @extensions[oid].merge!(:values => values, :critical => critical)
        end
      end

      ## Extension の削除
      def delete(oid)
        @extensions.delete(oid)
      end

      ## Extensions のエンコード
      def encode
        @extensions.each_pair do |key, elements|
          values = elements[:values]
          critical = elements[:critical] || false
          case key
          when 'authorityKeyIdentifier'
            @encoded_extensions << encode_authority_key_identifier(key, values, critical)
          when 'crlNumber'
            @encoded_extensions << encode_crl_number(key, values, critical)
          else
            type = elements[:type] || :default
            ## TODO: 指定したタイプごとの処理の追加
            case type
            when :bit_string
              @encoded_extensions << encode_bit_string_type(key, values, critical)
            when :enumerated
              case key
              when 'CRLReason'
                @encoded_extensions = OpenSSL::X509::Extension.new(key, values[0])
              else
                ## TODO: OpenSSL::X509::ExtensionFactory にすべきか検討する
                values.each do |value|
                  @encoded_extensions << OpenSSL::X509::Extension.new(key, value, critical)
                end
              end
            when :default
              @encoded_extensions << @extension_factory.create_ext(oid(key), values.join(','), critical)
            else
              raise ZZZ::CA::Error
            end
          end
        end
        @encoded_extensions
      end

      private
      ## BitString 型にエンコード
      def encode_bit_string_type(key, values, critical)
        encoded_values = ''
        values.each do |value|
          encoded_values << OpenSSL::ASN1::BitString(value.to_i(2).chr).to_der
        end
        OpenSSL::X509::Extension.new(key, encoded_values, critical)
      end

      ## oid の取得
      def oid(key)
        OpenSSL::X509::Extension.new(key, 'temporary').oid
      end

      ## crlNumber を ASN.1 形式にエンコード
      def encode_crl_number(key, values, critical)
        encoded_values = OpenSSL::ASN1::Integer(values[0]).to_der
        OpenSSL::X509::Extension.new(key, encoded_values, critical)
      end

      ## authorityKeyIdentifier を ASN.1 形式にエンコード
      def encode_authority_key_identifier(key, values, critical)
        encoded_values = ''
        values.each do |value|
          case value
          when /^keyid:true$/i
            v = OpenSSL::Digest::SHA1.digest(public_key.to_der)
            key_id = OpenSSL::ASN1::ASN1Data.new(
              v,
              OpenSSL::ASN1::EOC,
              :CONTEXT_SPECIFIC).to_der
              encoded_values = OpenSSL::ASN1::Sequence([key_id]).to_der
          else
            encoded_values = value
          end
        end
        OpenSSL::X509::Extension.new(key, encoded_values, critical)
      end

      ## 公開鍵の取得
      def public_key
        ## TODO: 書き直す
        certificate = @extension_factory.issuer_certificate || @extension_factory.subject_request || (raise ZZZ::CA::Error)
        certificate.public_key
      end
    end
  end
end
