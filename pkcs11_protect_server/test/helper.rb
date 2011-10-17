def open_ctsw
  PKCS11::ProtectServer::Library.new(:sw, :flags=>0)
end

def adjust_parity(data)
  out = []
  count_digit = "1"
  data.each_byte{|b|
    b &= 0xfe
    b |= 1 if b.to_s(2).count(count_digit) % 2 == 0
    out << b
  }
  return out.pack("C*")
end
