# -*- coding: utf-8 -*-

module ZZZ
  module CA
    class SubjectEncoder
      require 'openssl'

      attr_reader :subject

      def initialize(subject = [])
        @subject = subject
      end

      ## OID の追加
      def add(oid, value)
        @subject << {oid => value}
      end

      ## OID の削除
      def delete(oid)
        origin = @subject.dup
        @subject.select! {|dn| dn if dn[oid].nil? }
        (origin - @subject)
      end

      ## DN のエンコード
      def encode
        @encoded_subject = OpenSSL::X509::Name.new
        @subject.each do |element|
          element.each do |oid, value|
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
