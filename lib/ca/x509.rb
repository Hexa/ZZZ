#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-
module CA
  class X509

    attr_reader :private_key

    def initialize(type)
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

    def gen_private_key(params = {})
      @private_key = CA::Utils::gen_pkey(params)
    end

    def private_key=(private_key)
      @private_key = if private_key.instance_of(String)
                       CA::Utils::get_pkey_object(private_key)
                     else
                       private_key
                     end
    end

    ## 秘密鍵を暗号化して取得
    def encrypted_private_key(params)
      algorithm = params[:algorithm]
      passphrase = params[:passphrase]
      @private_key.export(CA::Utils::cipher(algorithm), passphrase)
    end

    def signature_algorithm
      # Certificate#signature_algorithm == 'itu-t' は署名前
      case @x509.signature_algorithm
      when 'itu-t'
        @signature_algorithm
      else
        method_missing(:signature_algorithm, [])
      end
    end

    ## この証明書を発行する CA の証明書の指定
    def issuer_certificate=(certificate)
      @certificates[:issuer_certificate] = CA::Utils::gen_x509_object(certificate)
    end

    def issuer_certificate
      @certificates[:issuer_certificate]
    end

    ## この証明書の発行元になる CSR の指定
    def subject_request=(request)
      @certificates[:subject_request] = CA::Utils::gen_x509_object(request)
    end

    def subject_request
      @certificates[:subject_request]
    end
  end
end
