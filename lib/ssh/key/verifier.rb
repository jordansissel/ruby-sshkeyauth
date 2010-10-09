#!/usr/bin/env ruby

require "rubygems"
require "net/ssh"
require "etc"

module SSH; module Key; class Verifier
  attr_accessor :account
  attr_accessor :sshd_config_file
  attr_accessor :logger

  # We only support protocol 2 public keys.
  # protocol2 is: options keytype b64key comment
  AUTHORIZED_KEYS_REGEX = 
    /^((?:[A-Za-z0-9-]+(?:="[^"]+")?,?)+ *)?(ssh-(?:dss|rsa)) *([^ ]*) *(.*)/

  # A new SSH Key Verifier.
  #
  # * account - optional string username. Should be a valid user on the system.
  #
  # If account is nil or omitted, then it defaults to the user running
  # this process (current user)
  def initialize(account=nil)
    if account == nil
      account = Etc.getlogin
    end

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

  # Can we validate 'original' against the signature(s)?
  #
  # * signature - a single SSH::Key::Signature or 
  #   hash of { identity => signature } values.
  # * original - the original string to verify against
  #
  # See also: SSH::Key::Signer#sign
  def verify?(signature, original)
    results = verify(signature, original)
    results.each do |identity, verified|
      if verified
        return true
      end
    end
    return false
  end # def verify?

  def verify_one(signature, original)
    identity = :default
    results = verify( { identity => signatures }, original)
    return results[identity]
  end # def verify_one

  def verify(signatures, original)
    if !signatures.is_a(Hash)
      raise ArgumentError.new("Expected hash, got #{signatures.class.name}")
    end

    ensure_connected
    identities = verifying_identities
    results = {}
    signatures.each do |signer_id, signature|
      identities.each do |identity|
        results[identity] = identity.ssh_do_verify(signature.signature, original)
      end
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
      identity = Net::SSH::KeyFactory.load_data_public_key(line)
      # Add the '.comment' attribute to our key
      identity.extend(Net::SSH::Authentication::Agent::Comment)

      match = AUTHORIZED_KEYS_REGEX.match(line)
      if match
        identity.comment = match[-1] 
      else
        puts "No comment or could not parse #{line}"
      end
    end
    return keys
  end
end; end; end # class SSH::Key::Verifier
