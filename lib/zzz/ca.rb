#!/opt/local/bin/ruby1.9
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
    PUBLIC_KEY_ALGORITHMS[:RSA] = :RSA
    PUBLIC_KEY_ALGORITHMS[:DSA] = :DSA
  end
end
