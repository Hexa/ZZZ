# -*- coding: utf-8 -*-

require 'rspec'
require 'zzz/ca/subject_encoder'

describe ZZZ::CA::SubjectEncoder do
  context "インスタンスを生成した場合" do
    before do
      @subject_encoder = ZZZ::CA::SubjectEncoder.new
      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('CN', 'cn')
    end

    it "#add(oid, value) は追加した {oid => value} の配列を返すこと" do
      @subject_encoder.add('CN', 'cn1').should be_eql [{'C' => 'JP'}, {'CN' => 'cn'}, {'CN' => 'cn1'}]
    end

    it "#delete(oid) は oid 該当する要素を除いた {oid => value} の配列を返すこと" do
      @subject_encoder.delete('C').should be_eql [{'CN' => 'cn'}]
    end

    it "#encode は DN をエンコードした値（OpenSSL::X509::Name オブジェクト）を返すこと" do
      name = OpenSSL::X509::Name.new
      name.add_entry('C', 'JP')
      name.add_entry('CN', 'cn')
      @subject_encoder.encode.to_s.should be_eql name.to_s
    end

    after do
      @subject_encoder = nil
    end
  end

  context "インスタンス生成時にサブジェクトを指定した場合" do
    before do
      @array = [{'C' => 'JP'}, {'C' => 'JP'}, {'CN' => 'cn'},  {'CN' => 'cn'}]
      @name = OpenSSL::X509::Name.new
      @array.each do |e|
        e.each do |oid, value|
          @name.add_entry(oid, value)
        end
      end

      @subject_encoder = ZZZ::CA::SubjectEncoder.new(@array)
    end

    it { @subject_encoder.subject.should be_eql @array }
    it { @subject_encoder.encoded_subject.should be_nil }

    it "#add(oid, value) は追加した {oid => value} の配列を返すこと" do
      @subject_encoder.add('CN', 'cn').should be_eql (@array << {'CN' => 'cn'})
    end

    it "#delete(oid) は oid 該当する要素を除いた {oid => value} の配列を返すこと" do
      @subject_encoder.delete('C').should be_eql [{'CN' => 'cn'}, {'CN' => 'cn'}]
    end

    it "#encode は DN をエンコードした値（OpenSSL::X509::Name オブジェクト）を返すこと" do
      @subject_encoder.encode.should be_an_instance_of OpenSSL::X509::Name
      @subject_encoder.encode.to_s.should be_eql @name.to_s
    end

    it "#encode 後の #encoded_subject は DN をエンコードした値（OpenSSL::X509::Name オブジェクト）を返すこと" do
      @subject_encoder.encode
      @subject_encoder.encoded_subject.to_s.should be_eql @name.to_s
    end

    after do
      @name = nil
      @array = nil
      @subject_encoder = nil
    end
  end
end
