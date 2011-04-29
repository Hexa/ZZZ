#!/opt/local/bin/ruby
# -*- coding: utf-8 -*-

module RbCertificate

  class SubjectEncoder
    require 'openssl'
    include OpenSSL

    attr_reader :subject

    def initialize(subject = [])
      @subject = subject
    end

    def show
      @subject
    end

    # 追加された順番を保持
    def add(oid, value)
      @subject <<  {oid => value}
    end

    ## 指定した oid を全て削除
    def delete(oid)
      # [{oid => value},
      #  {oid => value}, 
      #  {oid => value}]
      subject = []
      @subject.each do |element|
        subject << element unless element.include?(oid)
      end
      @subject = subject
    end

    def encode
      @encoded_subject = X509::Name.new
      @subject.each do |element|
        element.each_pair do |oid, value|
          @encoded_subject.add_entry(oid, value)
        end
      end
      @encoded_subject
    end

    def encoded_subject
      # #encode 前の呼び出しは例外
      raise(Error, "") if @encoded_subject.nil?
      @encoded_subject
    end
  end
end
