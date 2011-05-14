require "rubygems"
require "rake"
require "rspec/core/rake_task"

APP_NAME = "ZZZ"
AUTHORS = ["Hexa"]
HOMEPAGE = "http://github.com/Hexa/ZZZ"
SUMMARY = "ZZZ is a certificate and crl issue library for the ssl application."
DESCRIPTION = <<-EOF
ZZZ is a certificate and crl issue library for the ssl application.
EOF
MAIL = "hexa.diary@gmail.com"
LIBS = ["lib"]
LICENSE = ""

task :files do
  spec_files = FileList["spec/**/*"]
  #doc_files = FileList["doc/source/**/*", "doc/Makefile"]
  doc_files = FileList["doc/*"]
  lib_files = FileList["lib/**/*"]
  rake_files = FileList["Rakefile"]
  version_files = FileList["VERSION"]
  license_files = FileList["LICENSE"]
  readme_files = FileList["README*"]
  RDOC_FILES = FileList.new do |f|
    [license_files, "README.rdoc"].each do |files|
      f.include(files)
    end
  end
  TEST_FILES = spec_files
  PKG_FILES = FileList.new do |f|
    [spec_files, doc_files, lib_files, rake_files, version_files, license_files, readme_files].each do |files|
      f.include(files)
    end
  end
end

desc "Generate gemspec"
task :gemspec => :files do |e|
  PKG_VERSION = File.open("VERSION", "rb") {|file| file.read }.strip!
  gemspec = <<-EOF
Gem::Specification.new do |s|
  s.name = %q{#{APP_NAME}}
  s.summary = %q{#{SUMMARY}}
  s.version = %q{#{PKG_VERSION}}
  s.homepage = %q{#{HOMEPAGE}}
  s.require_path = #{LIBS.inspect}
  s.authors = #{AUTHORS.inspect}
  s.email = %q{#{MAIL}}
  s.files = #{PKG_FILES.inspect}
  s.description = %q{#{DESCRIPTION}}
  s.test_files = #{TEST_FILES.inspect}
  s.rdoc_options << "--charset=UTF-8"
  s.extra_rdoc_files = #{RDOC_FILES.inspect}
  s.add_development_dependency('rspec')
  s.required_ruby_version = ">= #{RUBY_VERSION}"
  s.license = "#{LICENSE}"
end
  EOF
  File.open("#{APP_NAME}.gemspec", "wb") {|file| file.puts gemspec }
end

PKG = "pkg/"
directory PKG

desc "Generate package"
task :build => :gemspec do
  sh "gem build #{APP_NAME}.gemspec"
  mkdir PKG unless File.exists?(PKG)
  mv "#{APP_NAME}-#{PKG_VERSION}.gem", PKG
end

desc "Install package"
task :install => :build do
  sh "gem install #{PKG}/#{APP_NAME}-#{PKG_VERSION}.gem"
end

desc "Uninstall package"
task :uninstall do
  sh "gem uninstall #{APP_NAME}"
end

require 'rake/rdoctask'
Rake::RDocTask.new(:rdoc) do |rd|
  rd.main = "README.rdoc"
  rd.rdoc_files.include("README*", "lib/**/*.rb")
  rd.options << "-c UTF-8"
end

desc "run spec"
RSpec::Core::RakeTask.new do |t|
  t.pattern = "./spec/**/*_spec.rb"
end
