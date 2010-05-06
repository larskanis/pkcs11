#!/usr/bin/env ruby

# Load the correct version if it's a Windows binary gem
if RUBY_PLATFORM =~/(mswin|mingw)/i
  major_minor = RUBY_VERSION[ /^(\d+\.\d+)/ ] or
    raise "Oops, can't extract the major/minor version from #{RUBY_VERSION.dump}"
  require "#{major_minor}/pkcs11_ext"
else
  require 'pkcs11_ext'
end

require 'pkcs11/extensions'
