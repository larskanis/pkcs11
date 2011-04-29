# -*- coding: utf-8 -*-
# -*- ruby -*-

require 'rubygems'
require 'hoe'
require 'rake/extensiontask'
require 'rbconfig'

GENERATED_FILES = [
  'ext/pk11_struct_impl.inc',
  'ext/pk11_struct_def.inc',
  'ext/pk11_const_def.inc',
  'ext/pk11_struct.doc',
  'ext/pk11_thread_funcs.h',
  'ext/pk11_thread_funcs.c',
]

CLEAN.include GENERATED_FILES
CLEAN.include 'lib/pkcs11_ext.so'
CLEAN.include 'tmp'

hoe = Hoe.spec 'pkcs11' do
  developer('Ryosuke Kutsuna', 'ryosuke@deer-n-horse.jp')
  developer('GOTOU Yuuzou', 'gotoyuzo@notwork.org')
  developer('Lars Kanis', 'kanis@comcard.de')
  extra_dev_deps << ['yard', '>= 0.6']
  extra_dev_deps << ['rake-compiler', '>= 0.7']

  self.url = 'http://github.com/larskanis/pkcs11'
  self.summary = 'PKCS#11 binding for Ruby'
  self.description = 'This module allows Ruby programs to interface with "RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki)".'

  self.readme_file = 'README.rdoc'
  self.extra_rdoc_files << self.readme_file << 'ext/pk11.c'
  spec_extras[:extensions] = 'ext/extconf.rb'
  spec_extras[:files] = File.read_utf("Manifest.txt").split(/\r?\n\r?/)
  spec_extras[:files] += GENERATED_FILES
  spec_extras[:has_rdoc] = 'yard'
end

ENV['RUBY_CC_VERSION'] ||= '1.8.6:1.9.2'

Rake::ExtensionTask.new('pkcs11_ext', hoe.spec) do |ext|
  ext.ext_dir = 'ext'
  ext.cross_compile = true                # enable cross compilation (requires cross compile toolchain)
  ext.cross_platform = ['i386-mswin32', 'i386-mingw32']     # forces the Windows platform instead of the default one
end

file 'ext/extconf.rb' => ['ext/pk11_struct_def.inc', 'ext/pk11_thread_funcs.c']
file 'ext/pk11_struct_def.inc' => 'ext/generate_structs.rb' do
  sh "#{Config::CONFIG['ruby_install_name']} ext/generate_structs.rb --def ext/pk11_struct_def.inc --impl ext/pk11_struct_impl.inc --doc ext/pk11_struct.doc ext/include/pkcs11t.h"
end
file 'ext/pk11_struct_impl.inc' => 'ext/pk11_struct_def.inc'
file 'ext/pk11_const_def.inc' => 'ext/generate_constants.rb' do
  sh "#{Config::CONFIG['ruby_install_name']} ext/generate_constants.rb --const ext/pk11_const_def.inc ext/include/pkcs11t.h"
end
file 'ext/pk11.c' => ['ext/pk11_struct_def.inc', 'ext/pk11_struct_impl.inc', 'ext/pk11_struct_macros.h']
file 'ext/pk11_const.c' => ['ext/pk11_const_def.inc', 'ext/pk11_const_macros.h']

file 'ext/pk11_thread_funcs.h' => 'ext/generate_thread_funcs.rb' do
  sh "#{Config::CONFIG['ruby_install_name']} ext/generate_thread_funcs.rb --impl ext/pk11_thread_funcs.c --decl ext/pk11_thread_funcs.h ext/include/pkcs11f.h"
end
file 'ext/pk11_thread_funcs.c' => 'ext/pk11_thread_funcs.h'
file 'ext/pk11.h' => 'ext/pk11_thread_funcs.h'

desc "Generate static HTML documentation with YARD"
task :yardoc do
  sh "yardoc --title \"PKCS#11/Ruby Interface\" --no-private lib/**/*.rb ext/*.c ext/*.doc pkcs11-safenet/lib/**/*.rb pkcs11-safenet/ext/*.c pkcs11-safenet/ext/*.doc"
end

desc "Publish YARD to wherever you want."
task :publish_yard => [:yardoc] do
  rdoc_locations = hoe.rdoc_locations
  warn "no rdoc_location values" if rdoc_locations.empty?
  rdoc_locations.each do |dest|
    sh %{rsync -av --delete doc/ #{dest}}
  end
end

# RDoc-upload task for github (currently on rubyforge)
#
# require 'grancher/task'
# Grancher::Task.new do |g|
#   g.branch = 'gh-pages'         # alternatively, g.refspec = 'ghpages:/refs/heads/ghpages'
#   g.push_to = 'origin'
#   g.directory 'doc'
# end

# vim: syntax=ruby
