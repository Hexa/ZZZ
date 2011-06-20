# -*- coding: utf-8 -*-

require 'openssl'
require 'zzz/ca/error'

module ZZZ
  module CA
    class ExtensionEncoder
      def initialize(extensions = {})
        @extensions = extensions
        @extension_factory = OpenSSL::X509::ExtensionFactory.new
      end

      def method_missing(name, *args)
        case name.to_s
        when /^subject_request$/
          @extension_factory.subject_request
        when /^subject_request=$/
          request = if args[0].instance_of? String
                      OpenSSL::X509::Request.new(args[0])
                    else
                      args[0]
                    end
        @extension_factory.__send__(name, request)
        when /^(subject|issuer)_certificate=$/
          certificate = if args[0].instance_of? String
                          OpenSSL::X509::Certificate.new(args[0])
                        else
                          args[0]
                        end
        @extension_factory.__send__(name, certificate)
        when /^(.+)=$/
          @extension_factory.__send__(name, args)
        when /^(.+)$/
          @extension_factory.__send__(name)
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
          @extensions[oid].merge!({:values => values, :critical => critical, :type => type})
        else
          @extensions[oid].merge!({:values => values, :critical => critical})
        end
      end

      ## Extension の削除
      def delete(oid)
        @extensions.delete(oid)
      end

      ## エンコード済み Extensions の取得
      def get_encoded_extensions
        # #encode 呼び出し前は例外
        raise ZZZ::CA::Error if @encoded_extensions.nil?
        @encoded_extensions
      end

      ## Extensions のエンコード
      def encode
        @encoded_extensions = []
        @extensions.each_pair do |key, elements|
          values = elements[:values]
          critical = elements[:critical] || false
          extension = ''
          case key
          when "authorityKeyIdentifier"
            @encoded_extensions << encode_authority_key_identifier(key, values, critical)
          when "crlNumber"
            @encoded_extensions << encode_crl_number(key, values, critical)
          else
            type = elements[:type] || :default
            ## TODO: 指定したタイプごとの処理の追加
            case type
            when :bit_string
              @encoded_extensions << encode_bit_string_type(key, values, critical)
            when :enumerated
              @encoded_extensions << OpenSSL::X509::Extension.new(key, values[0])
            when :default
              oid = get_oid(key)
              @encoded_extensions << @extension_factory.create_ext(oid, values.join(','), critical)
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
        extension = ''
        values.each do |value|
          extension << OpenSSL::ASN1::BitString(value.to_i(2).chr).to_der
        end
        OpenSSL::X509::Extension.new(key, extension, critical)
      end

      ## oid の取得
      def get_oid(key)
        OpenSSL::X509::Extension.new(key, 'temporary').oid
      end

      ## crlNumber を ASN.1 形式にエンコード
      def encode_crl_number(key, values, critical)
        extension = OpenSSL::ASN1::Integer(values[0]).to_der
        OpenSSL::X509::Extension.new(key, extension, critical)
      end

      ## authorityKeyIdentifier を ASN.1 形式にエンコード
      def encode_authority_key_identifier(key, values, critical)
        extension = ''
        values.each do |value|
          case value
          when /^keyid:true$/i
            public_key =  get_public_key(@extension_factory)
            v = OpenSSL::Digest::SHA1.digest(public_key.to_der)
            key_id = OpenSSL::ASN1::ASN1Data.new(
              v,
              OpenSSL::ASN1::EOC,
              :CONTEXT_SPECIFIC).to_der
              extension = OpenSSL::ASN1::Sequence([key_id]).to_der
          else
            extension = value
          end
        end
        OpenSSL::X509::Extension.new(key, extension, critical)
      end

      def get_public_key(extension_factory)
        if extension_factory.issuer_certificate
          extension_factory.issuer_certificate.public_key
        elsif extension_factory.subject_request
          extension_factory.subject_request.public_key
        else
          raise ZZZ::CA::Error
        end
      end
    end
  end
end
