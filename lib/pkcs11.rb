#!/usr/bin/env ruby

# Load the extension, depending of the ruby version
major_minor = RUBY_VERSION[ /^(\d+\.\d+)/ ] or
  raise "Oops, can't extract the major/minor version from #{RUBY_VERSION.dump}"
require "#{major_minor}/pkcs11_ext"
require 'pkcs11/extensions'
