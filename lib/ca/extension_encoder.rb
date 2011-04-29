#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

module CA
  class Extension
    require 'openssl'
    include OpenSSL

    def initialize(extensions = {})
      @extensions = extensions
      @extension_factory = X509::ExtensionFactory.new
    end

    def subject_request(element)
      if element.instance_of?(String)
        OpenSSL::X509::Request.new(element)
      else
        element
      end
    end

    def method_missing(name, *args)
      case name.to_s
      when /^subject_request$/
        @extension_factory.subject_request
      when /^subject_request=$/
        request = if args[0].instance_of? String
                        X509::Request.new(args[0])
                      else
                        args[0]
                      end
        @extension_factory.__send__(name, request)
      when /^(subject|issuer)_certificate=$/
        certificate = if args[0].instance_of? String
                        X509::Certificate.new(args[0])
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

    def show
      @extensions
    end

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

    def delete(oid)
      @extensions.delete(oid)
    end

    # #encode 呼び出し前は例外
    def get_encoded_extensions
      raise(Error) if @encoded_extensions.nil?
      @encoded_extensions
    end

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
          when :default
            oid = get_oid(key)
            @encoded_extensions << @extension_factory.create_ext(oid, values.join(','), critical)
          else
            raise(RbCertificate::Error, "Invalid type: #{type}.")
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
        extension << ASN1::BitString(value.to_i(2).chr).to_der
      end
      X509::Extension.new(key, extension, critical)
    end

    ## oid の取得
    def get_oid(key)
      X509::Extension.new(key, 'temporary').oid
    end

    ## crlNumber を ASN.1 形式にエンコード
    def encode_crl_number(key, values, critical)
      extension = ASN1::Integer(values[0]).to_der
      X509::Extension.new(key, extension, critical)
    end

    ## authorityKeyIdentifier を ASN.1 形式にエンコード
    def encode_authority_key_identifier(key, values, critical)
      extension = ''
      values.each do |value|
        case value
        when /^keyid:true$/i
          public_key =  get_public_key(@extension_factory)
          v = Digest::SHA1.digest(public_key.to_der)
          key_id = ASN1::ASN1Data.new(
            v,
            ASN1::EOC,
            :CONTEXT_SPECIFIC).to_der
          extension = ASN1::Sequence([key_id]).to_der
        else
          extension = value
        end
      end
      X509::Extension.new(key, extension, critical)
    end

    def get_public_key(extension_factory)
      if extension_factory.issuer_certificate
        extension_factory.issuer_certificate.public_key
      elsif extension_factory.subject_request
        extension_factory.subject_request.public_key
      else
        raise(Error, "NotFound public_key: .")
      end
    end
  end
end
