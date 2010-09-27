# -*- coding: utf-8 -*-
# -*- ruby -*-

require 'rubygems'
require 'hoe'
require 'rake/extensiontask'

CLEAN.include 'ext/pk11_struct_def.inc'
CLEAN.include 'ext/pk11_struct_impl.inc'
CLEAN.include 'ext/pk11_const_def.inc'
CLEAN.include 'lib/pkcs11_ext.so'
CLEAN.include 'tmp'

hoe = Hoe.spec 'pkcs11' do
  developer('Ryosuke Kutsuna', 'ryosuke@deer-n-horse.jp')
  developer('GOTOU Yuuzou', 'gotoyuzo@notwork.org')
  developer('Lars Kanis', 'kanis@comcard.de')

  self.url = 'http://github.com/larskanis/pkcs11'
  self.summary = 'PKCS#11 binding for Ruby'
  self.description = 'This module allows Ruby programs to interface with "RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki)".'

  self.readme_file = 'README.rdoc'
  self.extra_rdoc_files << self.readme_file << 'ext/pk11.c'
  spec_extras[:extensions] = 'ext/extconf.rb'
  spec_extras[:files] = File.read_utf("Manifest.txt").split(/\r?\n\r?/)
  spec_extras[:files] << 'ext/pk11_struct_impl.inc'
  spec_extras[:files] << 'ext/pk11_struct_def.inc'
end

ENV['RUBY_CC_VERSION'] = '1.8.6:1.9.1'

Rake::ExtensionTask.new('pkcs11_ext', hoe.spec) do |ext|
  ext.ext_dir = 'ext'
  ext.cross_compile = true                # enable cross compilation (requires cross compile toolchain)
  ext.cross_platform = ['i386-mswin32', 'i386-mingw32']     # forces the Windows platform instead of the default one
end

file 'ext/extconf.rb' => 'ext/pk11_struct_def.inc'
file 'ext/pk11_struct_def.inc' => 'ext/generate_structs.rb' do
  sh "ruby ext/generate_structs.rb --def ext/pk11_struct_def.inc --impl ext/pk11_struct_impl.inc --const ext/pk11_const_def.inc ext/include/pkcs11t.h"
end
file 'ext/pk11_struct_impl.inc' => 'ext/pk11_struct_def.inc'
file 'ext/pk11.c' => 'ext/pk11_struct_def.inc'
file 'ext/pk11_const.c' => 'ext/pk11_struct_def.inc'

# RDoc-upload task for github (currently on rubyforge)
#
# require 'grancher/task'
# Grancher::Task.new do |g|
#   g.branch = 'gh-pages'         # alternatively, g.refspec = 'ghpages:/refs/heads/ghpages'
#   g.push_to = 'origin'
#   g.directory 'doc'
# end

# vim: syntax=ruby
