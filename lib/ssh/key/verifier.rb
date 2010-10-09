#!/usr/bin/env ruby

require "rubygems"
require "net/ssh"
require "etc"

class SSHKeyVerifier
  attr_accessor :account
  attr_accessor :sshd_config_file
  attr_accessor :logger

  def initialize(account)
    @account = account
    @agent = Net::SSH::Authentication::Agent.new
    @use_agent = true
    @sshd_config_file = "/etc/ssh/sshd_config"
    @logger = Logger.new(STDERR)
  end # def initialize

  def ensure_connected
    begin
      @agent.connect! if !@agent.socket
    rescue Net::SSH::Authentication::AgentNotAvailable => e
      @use_agent = false
    end
  end # def ensure_connected

  def verify?(signature, original)
    results = verify(signature, original)
    results.each do |identity, verified|
      if verified
        return true
      end
    end
    return false
  end # def verify?

  def verify(signature, original)
    if signature.is_a? SSHKeySignature
      signature = signature.signature
    end

    ensure_connected
    identities = verifying_identities
    results = {}
    identities.each do |identity|
      results[identity] = identity.ssh_do_verify(signature, original)
    end
    return results
  end

  def verifying_identities
    identities = []
    @agent.identities.each { |id| identities << id }

    # Verifying should include your authorized_keys file, too, if we can find it.
    authorized_keys.each { |id| identities << id }
  end

  def authorized_keys
    if !File.exists?(@sshd_config_file)
      @logger.warn("No sshd_config file found '#{@sshd_config_file}'. Won't check for authorized keys files")
      return []
    end

    # Look up the @account's home directory.
    begin
      account_info = Etc.getpwnam(@account)
    rescue ArgumentError => e
      @logger.warn("User '#{@account}' does not exist.")
    end
    # TODO(sissel): It's not clear how we should handle empty homedirs, if
    # that happens?

    # Get the last AuthorizedKeysFile definition in the config.
    begin
      authorized_keys_file = File.new(@sshd_config_file).grep(/^\s*AuthorizedKeysFile/)[-1].split(" ")[-1]
    rescue 
      @logger.info("No AuthorizedKeysFile setting found in #{@sshd_config_file}, assuming '.ssh/authorized_keys'")
      authorized_keys_file = ".ssh/authorized_keys"
    end

    # Support things sshd_config does.
    authorized_keys_file.gsub!(/%%/, "%")
    authorized_keys_file.gsub!(/%u/, @account)
    if authorized_keys_file =~ /%h/
      if account_info == nil
        @logger.warn("No homedirectory for #{@account}, skipping authorized_keys")
        return []
      end

      authorized_keys_file.gsubs!(/%h/, account_info.dir)
    end

    # If relative path, use the homedir.
    if authorized_keys_file[0] != "/" 
      if account_info == nil
        @logger.warn("No homedirectory for #{@account}, skipping authorized_keys")
        return []
      end

      authorized_keys_file = "#{account_info.dir}/#{authorized_keys_file}"
    end

    if !File.exists?(authorized_keys_file)
      @logger.info("User '#{@account}' has no authorized keys file '#{authorized_keys_file}'")
      return []
    end

    keys = []
    @logger.info("AuthorizedKeysFile ==> #{authorized_keys_file}")
    File.new(authorized_keys_file).each do |line|
      next if line =~ /^\s*$/    # Skip blanks
      next if line =~ /^\s*\#$/  # Skip comments
      keys << Net::SSH::KeyFactory.load_data_public_key(line)
    end
    return keys
  end
end # class SSHKeyAuth
