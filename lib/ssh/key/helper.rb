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
    hostkey = %x{ssh-keygen -F "#{hostname}"}.split("\n")[1].chomp.split(" ",2)[-1] rescue nil
    if hostkey == nil
      raise SSH::Key::KeyNotFound.new("Could not find host key '#{hostname}' " \
                                       "in known_hosts (using ssh-keygen -F)")
    end
    @keys << Net::SSH::KeyFactory.load_data_public_key(hostkey)
  end

  # Add a public key from a ublic key string
  def add_public_key_data(data)
    @logger.info "Adding key from data #{data}"
    @keys << Net::SSH::KeyFactory.load_data_public_key(data)
  end # def add_key_file
end; end; end # module SSH::Key::Helper
