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

Hoe.plugin :bundler

# Build a Manifest file to satisfy hoe.
IO.write("Manifest.txt", `git ls-files`)

# Ensure pkg is rebuilt
task :remove_pkg do
  rm_rf 'pkg'
end
task :gem => [:remove_pkg]

hoe = Hoe.spec 'pkcs11' do
  developer('Ryosuke Kutsuna', 'ryosuke@deer-n-horse.jp')
  developer('GOTOU Yuuzou', 'gotoyuzo@notwork.org')
  developer('Lars Kanis', 'kanis@comcard.de')
  extra_dev_deps << ['yard', '~> 0.6']
  extra_dev_deps << ['rake-compiler', '~> 1.0']
  extra_dev_deps << ['rake-compiler-dock', '~> 1.2']
  extra_dev_deps << ['minitest', '~> 5.7']
  extra_dev_deps << ['hoe-bundler', '~> 1.0']

  self.summary = 'PKCS#11 binding for Ruby'
  self.description = 'This module allows Ruby programs to interface with "RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki)".'

  self.readme_file = 'README.rdoc'
  self.extra_rdoc_files << self.readme_file << 'ext/pk11.c'
  spec_extras[:extensions] = 'ext/extconf.rb'
  spec_extras[:files] = `git ls-files`.split("\n").reject{|f| f=~/^pkcs11_/ }
  spec_extras[:files] += GENERATED_FILES
  spec_extras[:required_ruby_version] = '>= 2.2.0'
  self.rdoc_locations << "http://www.rubydoc.info/gems/pkcs11"
end

Rake::ExtensionTask.new('pkcs11_ext', hoe.spec) do |ext|
  ext.ext_dir = 'ext'
  ext.cross_compile = true                # enable cross compilation (requires cross compile toolchain)
  ext.cross_platform = ['x86-mingw32', 'x64-mingw32', 'x86-linux', 'x86_64-linux']
end

file 'ext/extconf.rb' => ['ext/pk11_struct_def.inc', 'ext/pk11_thread_funcs.c']
file 'ext/pk11_struct_def.inc' => 'ext/generate_structs.rb' do
  sh "#{RbConfig::CONFIG['ruby_install_name']} ext/generate_structs.rb --def ext/pk11_struct_def.inc --impl ext/pk11_struct_impl.inc --doc ext/pk11_struct.doc ext/include/pkcs11t.h"
end
file 'ext/pk11_struct_impl.inc' => 'ext/pk11_struct_def.inc'
file 'ext/pk11_struct.doc' => 'ext/pk11_struct_def.inc'

file 'ext/pk11_const_def.inc' => 'ext/generate_constants.rb' do
  sh "#{RbConfig::CONFIG['ruby_install_name']} ext/generate_constants.rb --const ext/pk11_const_def.inc ext/include/pkcs11t.h"
end
file 'ext/pk11.c' => ['ext/pk11_struct_def.inc', 'ext/pk11_struct_impl.inc', 'ext/pk11_struct_macros.h']
file 'ext/pk11_const.c' => ['ext/pk11_const_def.inc', 'ext/pk11_const_macros.h']

file 'ext/pk11_thread_funcs.h' => 'ext/generate_thread_funcs.rb' do
  sh "#{RbConfig::CONFIG['ruby_install_name']} ext/generate_thread_funcs.rb --impl ext/pk11_thread_funcs.c --decl ext/pk11_thread_funcs.h ext/include/pkcs11f.h"
end
file 'ext/pk11_thread_funcs.c' => 'ext/pk11_thread_funcs.h'
file 'ext/pk11.h' => 'ext/pk11_thread_funcs.h'

# To reduce the gem file size strip mingw32 dlls before packaging
ENV['RUBY_CC_VERSION'].to_s.split(':').each do |ruby_version|
  task "tmp/x86-mingw32/stage/lib/#{ruby_version[/^\d+\.\d+/]}/pkcs11_ext.so" do |t|
    sh "i686-w64-mingw32-strip -S tmp/x86-mingw32/stage/lib/#{ruby_version[/^\d+\.\d+/]}/pkcs11_ext.so"
  end

  task "tmp/x64-mingw32/stage/lib/#{ruby_version[/^\d+\.\d+/]}/pkcs11_ext.so" do |t|
    sh "x86_64-w64-mingw32-strip -S tmp/x64-mingw32/stage/lib/#{ruby_version[/^\d+\.\d+/]}/pkcs11_ext.so"
  end
end

desc "Build windows and Linux binary gems per rake-compiler-dock."
task "gem:native" do
  require "rake_compiler_dock"
  RakeCompilerDock.sh <<-EOT
    rake cross native gem MAKE='nice make -j`nproc`'
  EOT
end

task :docs_of_vendor_extensions do
  Dir['pkcs11_luna', 'pkcs11_protect_server'].each do |dir|
    chdir(dir) do
      sh "rake doc_files"
    end
  end
end

desc "Generate static HTML documentation with YARD"
task yardoc: ['ext/pk11_struct.doc', :docs_of_vendor_extensions] do
  luna_docs = "pkcs11_luna/lib/**/*.rb pkcs11_luna/ext/*.c pkcs11_luna/ext/*.doc"
  sh "yardoc --title \"PKCS#11/Ruby Interface\" --no-private lib/**/*.rb ext/*.c ext/*.doc pkcs11_protect_server/lib/**/*.rb pkcs11_protect_server/ext/*.c pkcs11_protect_server/ext/*.doc #{luna_docs} - pkcs11_protect_server/README_PROTECT_SERVER.rdoc pkcs11_luna/README_LUNA.rdoc"
end

desc "Publish YARD to wherever you want."
task publish_yard:  [:yardoc] do
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
