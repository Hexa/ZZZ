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
        @extensions.each do |key, elements|
          values = elements[:values]
          critical = elements[:critical] || false
          type = elements[:type] || :default

          @encoded_extensions << case type
                                 when :default
                                   encode_ext_default(key, values, critical)
                                 when :bit_string
                                   encode_ext_bit_string(key, values, critical)
                                 when :enumerated
                                   encode_ext_enumerated(key, values, critical)
                                 else
                                   raise ZZZ::CA::Error
                                 end
        end
        @encoded_extensions
      end

      private
      def encode_ext_default(key, values, critical)
        case key
        when 'authorityKeyIdentifier'
          encode_authority_key_identifier(values.join(','), critical)
        when 'crlNumber'
          encode_crl_number(values, critical)
        else
          encode_ext_other(key, values.join(','), critical)
        end
      end

      def encode_ext_bit_string(key, values, critical)
        encode_bit_string_type(key, values, critical)
      end

      def encode_ext_enumerated(key, values, critical)
        case key
        when 'CRLReason'
          encode_crl_reqson(values[0])
        else
          ## TODO: OpenSSL::X509::ExtensionFactory にすべきか検討する
          OpenSSL::X509::Extension.new(key, values[0], critical)
        end
      end

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
      def encode_crl_number(values, critical)
        encoded_values = OpenSSL::ASN1::Integer(values[0]).to_der
        OpenSSL::X509::Extension.new('crlNumber', encoded_values, critical)
      end

      ## authorityKeyIdentifier を ASN.1 形式にエンコード
      def encode_authority_key_identifier(values, critical)
        @extension_factory.create_ext('authorityKeyIdentifier', values, critical)
      end

      ## CRLReason を ASN.1 形式にエンコード
      def encode_crl_reqson(reason)
         @encoded_extensions = OpenSSL::X509::Extension.new('CRLReason', reason)
      end
      
      def encode_ext_other(key, value, critical)
        @extension_factory.create_ext(oid(key), value, critical)
      end
    end
  end
end
