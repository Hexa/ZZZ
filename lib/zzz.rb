#!/opt/local/bin/ruby1.9
# -*- coding: utf-8 -*-

require File.join(File.expand_path(File.dirname(__FILE__)), "zzz", "ca")

module ZZZ
  VERSION ||= File.open(File.join(File.expand_path(File.dirname(__FILE__)), "../", "VERSION"), 'rb') { |file| file.read.strip! }
end
