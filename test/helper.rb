require "openssl"

def open_softokn
  lLIBSOFTOKEN3_SO = "libsoftokn3.so"
  lLIBNSS_PATHS = %w(
    /usr/lib64 /usr/lib/ /usr/lib64/nss /usr/lib/nss
  )
  unless so_path = ENV['SOFTOKN_PATH']
    paths = lLIBNSS_PATHS.collect{|path| File.join(path, lLIBSOFTOKEN3_SO) }
    so_path = paths.find{|path| File.exist?(path) }
  end

  dir = Dir.glob(File.expand_path("~/.mozilla/firefox/*.default")).first
  #dir = 'D:/kueche/.mozilla/firefox/08mlxvfo.default'
  nNSS_INIT_ARGS = [
  "configDir='#{dir}'",
  "secmod='secmod.db'",
  "flags='readOnly'",
  ]

  pk11 = PKCS11.new(so_path, :flags=>0, :pReserved=>nNSS_INIT_ARGS.join(" "))
end
