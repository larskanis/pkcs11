require "pkcs11"

def find_softokn
  if RUBY_PLATFORM =~ /mswin|mingw/
    lLIBSOFTOKEN3_SO = "softokn3.dll"

    # Try to find the firefox path.
    unless ENV['SOFTOKN_PATH']
      require 'win32/registry'
      begin
        firefox_path = Win32::Registry::HKEY_LOCAL_MACHINE.open('SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe'){|reg|
          reg.read('Path')[1]
        }
      rescue Win32::Registry::Error
      end
      if firefox_path
        ENV['Path'] = ENV['Path'] + ";" + firefox_path
        so_path = File.join(firefox_path, lLIBSOFTOKEN3_SO)
      end
    end
  else
    lLIBSOFTOKEN3_SO = "libsoftokn3.so"
    lLIBNSS_PATHS = %w(
      /usr/lib64
      /usr/lib
      /usr/lib64/nss
      /usr/lib/nss
      /usr/lib/i386-linux-gnu/nss
      /usr/lib/x86_64-linux-gnu/nss
    )
    unless so_path = ENV['SOFTOKN_PATH']
      paths = lLIBNSS_PATHS.collect{|path| File.join(path, lLIBSOFTOKEN3_SO) }
      so_path = paths.find do |path|
        File.exist?(path) && open_softokn(path).close rescue false
      end
    end
  end

  raise "#{lLIBSOFTOKEN3_SO} not found - please install firefox or libnss3 or set ENV['SOFTOKN_PATH']" unless so_path
  so_path
end

def softokn_params
  dir = File.join(File.dirname(__FILE__), 'fixtures/softokn')
  [
  "configDir='#{dir}'",
  "secmod='secmod.db'",
  "flags='readWrite'",
  ]
end

def softokn_params_string
  softokn_params.join(" ")
end

def open_softokn(so_path=nil)
  PKCS11.open(so_path || find_softokn, :flags=>0, :pReserved=>softokn_params_string)
end
