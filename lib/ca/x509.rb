#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-
module CA
  class X509

    attr_reader :private_key

    def initialize
    end

    def method_missing(name, *args)
      case name.to_s
      when /^.+=$/
        @x509.__send__(name, args[0])
      when /^.+$/
        @x509.__send__(name)
      end
    end

    def gen_private_key(params)
      @private_key = CA::Utils::gen_private_key(params)
    end

    def private_key=(private_key)
      @private_key = if private_key.instance_of(String)
                       CA::Utils::get_pkey_object(private_key)
                     else
                       private_key
                     end
    end

    def pkcs12
    end

  end
end
