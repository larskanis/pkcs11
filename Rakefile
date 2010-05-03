# -*- coding: utf-8 -*-
# -*- ruby -*-

require 'rubygems'
require 'hoe'
require 'rake/extensiontask'

hoe = Hoe.spec 'pkcs11' do
  developer('Ryosuke Kutsuna', 'ryosuke@deer-n-horse.jp')
  developer('GOTOU Yuuzou', 'gotoyuzo@notwork.org')
  developer('Lars Kanis', 'kanis@comcard.de')

  require_paths = ['lib']
end

Rake::ExtensionTask.new('pkcs11', hoe.spec) do |ext|
  ext.cross_compile = true                # enable cross compilation (requires cross compile toolchain)
  ext.cross_platform = ['i386-mswin32', 'i386-mingw32']     # forces the Windows platform instead of the default one
end

# vim: syntax=ruby
