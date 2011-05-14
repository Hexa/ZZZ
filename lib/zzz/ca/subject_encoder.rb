#!/opt/local/bin/ruby
# -*- coding: utf-8 -*-

module ZZZ
  module CA
    class SubjectEncoder
      require 'openssl'

      attr_reader :subject

      def initialize(subject = [])
        @subject = subject
      end

      def show
        @subject
      end

      def add(oid, value)
        @subject <<  {oid => value}
      end

      def delete(oid)
        subject = []
        @subject.each do |element|
          subject << element unless element.include?(oid)
        end
        @subject = subject
      end

      def encode
        @encoded_subject = OpenSSL::X509::Name.new
        @subject.each do |element|
          element.each_pair do |oid, value|
            @encoded_subject.add_entry(oid, value)
          end
        end
        @encoded_subject
      end

      def encoded_subject
        @encoded_subject
      end
    end
  end
end
