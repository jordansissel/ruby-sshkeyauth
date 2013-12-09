require "net/ssh"

module SSH; module Key; class KeyNotFound < StandardError
end; end; end

module SSH; module Key; module Helper
  # Add a private key to this signer.
  def add_key_file(path, passphrase=nil)
    @logger.info "Adding key from file #{path} (with#{passphrase ? "" : "out"} passphrase)"
    @keys << Net::SSH::KeyFactory.load_private_key(path, passphrase)
  end # def add_key_file

  # Add a public key from your known_hosts file
  def add_key_from_host(hostname)
    hostkey = SSH::Key::Helper.known_host_key('/etc/ssh/ssh_known_hosts', hostname)
    if hostkey == nil
      hostkey = SSH::Key::Helper.known_host_key('~/.ssh/known_hosts', hostname)
      if hostkey == nil
        SSH::Key::KeyNotFound.new("Could not find host key '#{hostname}' " \
                                       "in known_hosts file")
      end
    end
    @keys << hostkey
  end

  # Add a public key from a ublic key string
  def add_public_key_data(data)
    @logger.info "Adding key from data #{data}"
    @keys << Net::SSH::KeyFactory.load_data_public_key(data)
  end # def add_key_file

  def self.known_host_key(host_file, hostname)
    @@known_hosts ||= {}
    keys = @@known_hosts[host_file] ||= read_keys(host_file)
    keys[hostname]
  end

  # adapted from Net::SSH::KnownHosts#keys_for(host)
  def self.read_keys(host_file)
      keys = {}
      return keys unless File.readable?(host_file)

      File.open(host_file) do |file|
        scanner = StringScanner.new("")
        file.each_line do |line|
          scanner.string = line

          scanner.skip(/\s*/)
          next if scanner.match?(/$|#/)

          hostlist = scanner.scan(/\S+/).split(/,/)

          scanner.skip(/\s*/)
          type = scanner.scan(/\S+/)

          next unless Net::SSH::KnownHosts::SUPPORTED_TYPE.include?(type)

          scanner.skip(/\s*/)
          blob = scanner.rest.unpack("m*").first
          key = Net::SSH::Buffer.new(blob).read_key

          # only store first key
          hostlist.each {|host|  keys[host] ||= key }
        end
      end

      keys
  end
end; end; end # module SSH::Key::Helper
