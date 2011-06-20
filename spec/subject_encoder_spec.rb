# -*- coding: utf-8 -*-

require 'rspec'
require 'time'
require 'openssl'
require 'zzz/ca/utils'
require 'zzz/ca/subject_encoder'

describe ZZZ::CA::SubjectEncoder do
  context "インスタンスを生成した場合" do
    before do
      @subject_encoder = ZZZ::CA::SubjectEncoder.new
    end

    it "#show は空の配列を返すこと" do
      @subject_encoder.show.should == []
    end

    it "#add(oid, value) は追加した {oid => value} の配列を返すこと" do
      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('CN', 'cn').should == [{'C' => 'JP'}, {'C' => 'JP'}, {'CN' => 'cn'}]
    end

    it "#delete(oid) は oid 該当する要素を削除した {oid => value} の配列を返すこと" do
      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('CN', 'cn')
      @subject_encoder.add('CN', 'cn')
      @subject_encoder.delete('C').should == [{'CN' => 'cn'}, {'CN' => 'cn'}]
    end

    it "#encode は DN をエンコードした値（OpenSSL::X509::Name オブジェクト）を返すこと" do
      name = OpenSSL::X509::Name.new
      name.add_entry('C', 'JP')
      name.add_entry('C', 'JP')
      name.add_entry('CN', 'cn')
      name.add_entry('CN', 'cn')

      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('CN', 'cn')
      @subject_encoder.add('CN', 'cn')
      @subject_encoder.encode.to_s.should == name.to_s
    end

    after do
      @subject = nil
    end
  end

  context "インスタンス生成時にサブジェクトを指定した場合" do
    before do
      @name = [{'C' => 'JP'}, {'C' => 'JP'}, {'CN' => 'cn'},  {'CN' => 'cn'}]
      @subject_encoder = ZZZ::CA::SubjectEncoder.new(@name)
    end

    it "#show は .new の引数で指定した配列を返すこと" do
      @subject_encoder.show.should == @name
    end

    it "#add(oid, value) は追加した {oid => value} の配列を返すこと" do
      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('CN', 'cn').should == (@name << [{'C' => 'JP'}, {'C' => 'JP'}, {'CN' => 'cn'}])
    end

    it "#delete(oid) は oid 該当する要素を削除した {oid => value} の配列を返すこと" do
      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('CN', 'cn')
      @subject_encoder.add('CN', 'cn')
      @subject_encoder.delete('C').should == [{'CN' => 'cn'}, {'CN' => 'cn'}, {'CN' => 'cn'}, {'CN' => 'cn'}]
    end

    it "#encode は DN をエンコードした値（OpenSSL::X509::Name オブジェクト）を返すこと" do
      name = OpenSSL::X509::Name.new
      name.add_entry('C', 'JP')
      name.add_entry('C', 'JP')
      name.add_entry('CN', 'cn')
      name.add_entry('CN', 'cn')
      name.add_entry('C', 'JP')
      name.add_entry('C', 'JP')
      name.add_entry('CN', 'cn')
      name.add_entry('CN', 'cn')

      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('C', 'JP')
      @subject_encoder.add('CN', 'cn')
      @subject_encoder.add('CN', 'cn')
      @subject_encoder.encode.to_s.should == name.to_s
    end

    after do
      @name = nil
      @subject = nil
    end
  end
end
