# -*- coding: utf-8 -*-

module ZZZ
  module CA
    class SubjectEncoder
      require 'openssl'

      attr_reader :subject

      def initialize(subject = [])
        @subject = subject
      end

      ## エンコード前の DN の取得
      def show
        @subject
      end

      ## OID の追加
      def add(oid, value)
        @subject << {oid => value}
      end

      ## OID の削除
      def delete(oid)
        @subject.map! {|dn| dn if dn[oid].nil? }.compact!
      end

      ## DN のエンコード
      def encode
        @encoded_subject = OpenSSL::X509::Name.new
        @subject.each do |element|
          element.each_pair do |oid, value|
            @encoded_subject.add_entry(oid, value)
          end
        end
        @encoded_subject
      end

      ## エンコード済み DN の取得
      def encoded_subject
        @encoded_subject
      end
    end
  end
end
