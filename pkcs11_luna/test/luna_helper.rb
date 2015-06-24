begin
  require 'io/console'
rescue LoadError
end

class LunaHelper
    
  @@slot = nil  
  @@password = nil
  
  def self.get_password(prompt)
    password = ""
    if STDIN.respond_to?(:echo=) and STDIN.respond_to?(:getch)
      print prompt
      STDIN.echo = false
      while true       
        c = STDIN.getch 
        if c.ord == 3
          STDIN.echo = true
          exit!
        end
        if [10, 13].include?(c.ord)
          print "\n"
          break
        end       
        if [8, 127].include?(c.ord)
          if password.length >= 1
            print 8.chr          
            print 32.chr
            print 8.chr
            password = password[0..-2]
          end
        else
          password << c
          print '*'
        end 
      end
      STDIN.echo = true 
    else      
      password = `read -s -p "#{prompt}" password; echo $password`.chomp
    end     
    password
  end
  
  
  def self.get_slot_password()
    if @@slot.nil?
      print "Enter slot id: "
      @@slot = gets
    end
    if @@password.nil?
      @@password = get_password("Enter user PIN : ")
    end
    return @@slot.to_i, @@password
  end
  
end