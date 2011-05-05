#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require File.join(File.expand_path(File.dirname(__FILE__)), "ca", "utils")
require File.join(File.expand_path(File.dirname(__FILE__)), "ca", "x509")
require File.join(File.expand_path(File.dirname(__FILE__)), "ca", "certificate")
require File.join(File.expand_path(File.dirname(__FILE__)), "ca", "request")
require File.join(File.expand_path(File.dirname(__FILE__)), "ca", "crl")
require File.join(File.expand_path(File.dirname(__FILE__)), "ca", "subject_encoder")
require File.join(File.expand_path(File.dirname(__FILE__)), "ca", "extension_encoder")


module CA
  X509_V1 = 0
  X509_V2 = 1
  X509_V3 = 2
  CSR_V1 = 0
  CSR_V2 = 1
  CRL_V1 = 0
  CRL_V2 = 1
end
