#!/usr/bin/env ruby
# This quick and dirty parser for PKCS#11 functions generates
# wrapper functions for using rb_thread_call_without_gvl()
# of Ruby 1.9+

require 'optparse'

options = Struct.new(:verbose, :impl, :decl).new
OptionParser.new do |opts|
	opts.banner = "Usage: #{$0} [options] <header-file.h>*"

	opts.on("-v", "--[no-]verbose", "Run verbosely", &options.method(:verbose=))
  opts.on("--decl FILE", "Write declarations to this file", &options.method(:decl=))
  opts.on("--impl FILE", "Write implementations to this file", &options.method(:impl=))
	opts.on_tail("-h", "--help", "Show this message") do
		puts opts
		exit
	end
end.parse!

Attribute = Struct.new(:type, :name)

File.open(options.decl, "w") do |fd_decl|
File.open(options.impl, "w") do |fd_impl|
fd_decl.puts <<-EOT
  #ifndef #{options.decl.gsub(/[^\w]/, "_").upcase}
  #define #{options.decl.gsub(/[^\w]/, "_").upcase}
  #include "pk11.h"
EOT
fd_impl.puts <<-EOT
  #include #{File.basename(options.decl).inspect}
EOT
ARGV.each do |file_h|
  c_src = IO.read(file_h)
  c_src.scan(/CK_PKCS11_FUNCTION_INFO\((.+?)\).*?\((.*?)\);/m) do
    func_name, func_param_list = $1, $2
    func_params = []
    func_param_list.scan(/^\s+([A-Z_0-9]+)\s+([\w_]+)/) do |elem|
      func_params << Attribute.new($1, $2)
    end
    puts "func_name:#{func_name.inspect} func_params: #{func_params.inspect}" if options.verbose

    fd_decl.puts <<-EOT
      struct tbr_#{func_name}_params {
        CK_#{func_name} func;
        struct { #{ func_params.map{|f| f.type+" "+f.name+";"}.join } } params;
        CK_RV retval;
      };
      void * tbf_#{func_name}( void *data );

    EOT
    fd_impl.puts <<-EOT
      void * tbf_#{func_name}( void *data ){
        struct tbr_#{func_name}_params *p = (struct tbr_#{func_name}_params*)data;
        p->retval = p->func( #{func_params.map{|f| "p->params."+f.name}.join(",") } );
        return NULL;
      }

    EOT
  end
end
fd_decl.puts <<-EOT
  #endif
EOT
end
end
