require 'openssl'
require 'io/console'

module PasswordSafe
  VERSION = '0.0.1'

  class Error < StandardError
  end

  class Record
    Field = Struct.new(:sym, :id, :type)

    @@h = [
      Field.new(:version, 0x00, :short),
      Field.new(:uuid, 0x01, :uuid),
      Field.new(:ndef_pref, 0x02, :text),
      Field.new(:tree_disp_stat, 0x03, :text),
      Field.new(:last_save_time, 0x04, :time),
      Field.new(:last_save_who, 0x05, :text),
      Field.new(:last_save_what, 0x06, :text),
      Field.new(:last_save_user, 0x07, :text),
      Field.new(:last_save_host, 0x08, :text),
      Field.new(:db_name, 0x09, :text),
      Field.new(:db_desc, 0x0a, :text),
      Field.new(:db_filters, 0x0b, :text),
      Field.new(:reserved, 0x0c, :text),
      Field.new(:reserved, 0x0d, :text),
      Field.new(:reserved, 0x0e, :text),
      Field.new(:recently_used, 0x0f, :text),
      Field.new(:names_pwd_policies, 0x10, :text),
      Field.new(:empty_group, 0x11, :text),
      Field.new(:reserved, 0x12, :text),
      Field.new(:end, 0xff, :nil),
    ]

    @@r = [
      Field.new(:uuid, 0x01, :uuid),
      Field.new(:group, 0x02, :text),
      Field.new(:title, 0x03, :text),
      Field.new(:username, 0x04, :text),
      Field.new(:notes, 0x05, :text),
      Field.new(:password, 0x06, :text),
      Field.new(:create_time, 0x07, :time),
      Field.new(:modify_time, 0x08, :time),
      Field.new(:access_time, 0x09, :time),
      Field.new(:expiry_time, 0x0a, :time),
      Field.new(:last_modify_time_time, 0x0c, :time),
      Field.new(:url, 0x0d, :text),
      Field.new(:autotype, 0x0e, :text),
      Field.new(:pwd_history, 0x0f, :text),
      Field.new(:pwd_policy, 0x10, :text),
      Field.new(:pwd_expiry_int, 0x11, :short),
      Field.new(:run_command, 0x12, :text),
      Field.new(:dclick_action, 0x13, :short),
      Field.new(:email, 0x14, :text),
      Field.new(:protected, 0x15, :byte),
      Field.new(:pwd_symbols, 0x16, :text),
      Field.new(:sdclick_action, 0x17, :short),
      Field.new(:pwd_policy_name, 0x18, :short),
      Field.new(:end, 0xff, :nil),
    ]

    def initialize(header=false)
      @header = header
      @m = {}
    end

    def unmarshal(io, mac)
      len_data = io.read(4)
      type_data = io.read(1)

      len = len_data.unpack('V').first
      type = type_data.unpack('C').first
      rem = (5 + len) % 16

      data = io.read(len)
      rem_data = io.read(16 - rem) if rem != 0

      #puts "LEN = #{len}"
      #puts "mac < #{mac.digest.inspect}"
      mac.update(data)
      #puts "mac > #{mac.digest.inspect}"

      d = @header ? @@h : @@r

      #puts "F #{len} #{type} #{rem} (#{d.size})"

      field = d.select { |fld| fld.id == type }.first

      raise Error, "Invalid type #{type}" unless field

      val = nil
      case field.type
      when :byte
        val = data[0]
      when :short
        val = data[0,2].unpack('v').first
      when :uuid
        val = data.unpack('Z*').first
      when :text
        val = data.unpack('Z*').first
      when :time
        # TODO: try to parse from string
        val = data.unpack('V').first
      when :nil
      else
        raise Error, "Invalid field type #{field.type}"
      end

      @m[field.sym] = val if val

      val
    end

    def name
      if @m[:group]
        "#{@m[:group]}.#{@m[:title]}"
      else
        @m[:title]
      end
    end

    def has_field?(name)
      @m.has_key?(name)
    end

    def get_field(name)
      if name.to_sym == :name
        return self.name
      else
        @m[name.to_sym]
      end
    end

    def set_field(name, val)
      @m[name.to_sym] = val
    end

    def method_missing(*args)
      # TODO: automatically resolve [[UUID]]

      if args.size == 1
        @m[args[0]]
      elsif args.size == 2
        k = args[0].to_s
        raise Error, "Invalid method call #{args}" unless k.end_with? '='
        k.sub!(/=$/, '')
        @m[k.to_sym] = args[1]
      else
        raise Error, "Invalid method call #{args}"
      end
    end

    def each
      @m.each { |k,v| yield k, v }
    end

    def inspect
      items = []
      @m.each { |k,v| items << "#{k}=#{v.inspect}" }
      "<#{items.join(",\n")}>"
    end
  end

  require 'twofish'

  class KeychainV3
    attr_reader :header

    # http://sourceforge.net/p/passwordsafe/code/HEAD/tree/trunk/pwsafe/pwsafe/docs/formatV3.txt
    def initialize(path, readonly=false)
      throw Error, "Invalid path" unless File.exist? path

      @path = path
      @header = nil
      @records = nil

      # TODO: writeback and readonly
    end

    def strech(pwd, salt, iter)
      sha = OpenSSL::Digest::SHA256.new

      sha.reset
      sha << pwd
      sha << salt

      hash = sha.digest

      iter.times do
        sha.reset
        sha << hash
        hash = sha.digest
      end

      sha.digest
    end

    def parse_header(path, pwd)
      File.open(path) do |f|
        tag = f.read(4).unpack('Z4').first
        raise Error, "Invalid TAG" if tag != "PWS3"

        salt = f.read(32).unpack('a32').first
        iter = f.read(4).unpack('V').first
        p = strech(pwd, salt, iter)

        hp = f.read(32).unpack('a32').first
        raise Error, "Invalid password" if hp != OpenSSL::Digest::SHA256.digest(p)

        b12 = f.read(32).unpack('a32').first
        b3 = f.read(16).unpack('a16').first
        b4 = f.read(16).unpack('a16').first

        iv = f.read(16)

        #puts "p:",p.inspect
        #puts "b12:",b12.inspect

        ecb = Twofish.new(p, :mode => :ecb)
        k = ecb.decrypt(b12)
        l = ecb.decrypt(b3 + b4)

        #puts "k:",k.inspect

        cbc = Twofish.new(k, :mode => :cbc, :iv => iv)
        data = f.read
        eof = data.index("PWS3-EOFPWS3-EOF")
        hmac = data[eof + 16,32].unpack("a*").first
        #puts "hmac:", hmac.inspect
        raise Error, "Invalid data - couldn't find EOF marker" unless eof

        return l, hmac, cbc.decrypt(data[0..eof-1])
      end
    end

    # Ask user password and return it. *prompt* is printed before password
    # request and *interactive* argument specifies whether application
    # should open */dev/tty* to read password from (*true*) or use standard
    # input (*false*).
    def ask(prompt, visible=true, interactive=true)
      i, o = $stdin, $stdout

      begin
        i = o = open('/dev/tty', 'w+') if interactive
      rescue
        interactive = false
      end

      unless $silent
        o.print prompt
        o.flush
      end

      if i.tty? and not visible
        password = i.noecho(&:gets)
      else
        password = i.gets
      end

      unless $silent
        o.puts
        o.flush
        i.close if interactive
      end

      return password.sub(/\n$/, '')
    end

    def unlock(pwd=nil)
      pwd = ask('Password:', false) unless pwd
      l, hmac, text = parse_header(@path, pwd)
      io = StringIO.new(text)
      mac = OpenSSL::HMAC.new(l, OpenSSL::Digest::SHA256.new)

      @header = Record.new(true)
      while !io.eof
        break unless @header.unmarshal(io, mac)
      end

      ver = @header.version
      raise Error, "Unsupported version #{ver}" if ver < 0x0309

      @records = []
      r = Record.new
      while !io.eof
        unless r.unmarshal(io, mac)
          @records << r
          r = Record.new
        end
      end
      io.close

      raise Error, "Invalid HMAC" if mac.digest != hmac
    end

    def inspect
      puts @header.inspect
      puts
      puts @records.inspect
    end

    def each
      @records.each { |r| yield r }
    end

    def [](uuid)
      @records.select { |r| r.uuid == uuid }.first
    end

    def backup
      # TODO
    end

    def save
      # TODO
    end
  end
end
