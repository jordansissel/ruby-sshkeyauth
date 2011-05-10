#!/usr/bin/env ruby

require "rubygems"
require "net/ssh"
require "ssh/key/signature"
require "ssh/key/helper"
require "etc"

module SSH; module Key; class Verifier
  include SSH::Key::Helper

  attr_accessor :account
  attr_accessor :sshd_config_file
  attr_accessor :authorized_keys_file
  attr_accessor :logger
  attr_accessor :use_agent
  attr_accessor :use_authorized_keys

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
    @use_authorized_keys = true
    @sshd_config_file = "/etc/ssh/sshd_config"
    @authorized_keys_file = nil
    @logger = Logger.new(STDERR)
    @logger.level = $DEBUG ? Logger::DEBUG : Logger::WARN
    @keys = []
  end # def initialize

  def ensure_connected
    begin
      @agent.connect! if !@agent.socket
    rescue Net::SSH::Authentication::AgentNotAvailable => e
      @use_agent = false
      @logger.warn "SSH Agent not available"
    rescue => e
      @use_agent = false
      @logger.warn "Unexpected error ocurred. Disabling agent usage."
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
      return true if verified
    end
    return false
  end # def verify?

  # Verify an original with the signatures.
  # * signatures - a hash of { identity => signature } values
  #   or, it can be an array of signature strings
  #   or, it can simply be a signature string.
  # * original - the original string value to verify
  def verify(signatures, original)
    @logger.info "Getting identities"
    identities = verifying_identities
    @logger.info "Have #{identities.length} identities"
    results = {}

    if signatures.is_a? Hash
      @logger.debug("verify 'signatures' is a Hash")
      inputs = signatures.values
    elsif signatures.is_a? Array
      @logger.debug("verify 'signatures' is an Array")
      inputs = signatures
    elsif signatures.is_a? String
      @logger.debug("verify 'signatures' is an String")
      inputs = [signatures]
    end

    if inputs[0].is_a? SSH::Key::Signature
      @logger.debug("verify 'signatures' is an array of Signatures")
      inputs = inputs.collect { |i| i.signature }
    end

    inputs.each do |signature|
      identities.each do |identity|
        key = [signature, identity]
        results[key] = identity.ssh_do_verify(signature, original)
        @logger.info "Trying key #{identity.to_s.split("\n")[1]}... #{results[key]}"
      end
    end
    return results
  end # def verify

  def verifying_identities
    identities = []
    ensure_connected 
    if @use_agent
      begin
        @agent.identities.each { |id| identities << id }
      rescue ArgumentError => e
        @logger.warn("Error from agent query: #{e}")
        @use_agent = false
      end
    end

    if @use_authorized_keys
      # Verifying should include your authorized_keys file, too, if we can 
      # find it.
      authorized_keys.each { |id| identities << id }
    end

    @keys.each { |id| identities << id }
    return identities
  end # def verifying_identities

  def find_authorized_keys_file
    # Look up the @account's home directory.
    begin
      account_info = Etc.getpwnam(@account)
    rescue ArgumentError => e
      @logger.warn("User '#{@account}' does not exist.")
    end

    # TODO(sissel): It's not clear how we should handle empty homedirs, if
    # that happens?

    # Default authorized_keys location
    authorized_keys_file = ".ssh/authorized_keys"

    # Try to find the AuthorizedKeysFile definition in the config.
    if File.exists?(@sshd_config_file)
      begin
        authorized_keys_file = File.new(@sshd_config_file).grep(/^\s*AuthorizedKeysFile/)[-1].split(" ")[-1]
      rescue 
        @logger.info("No AuthorizedKeysFile setting found in #{@sshd_config_file}, assuming '#{authorized_keys_file}'")
      end
    else
      @logger.warn("No sshd_config file found '#{@sshd_config_file}'. Won't check for authorized keys files. Assuming '#{authorized_keys_file}'")
    end

    # Support things sshd_config does.
    authorized_keys_file.gsub!(/%%/, "%")
    authorized_keys_file.gsub!(/%u/, @account)
    if authorized_keys_file =~ /%h/
      if account_info == nil
        @logger.warn("No homedirectory for #{@account}, skipping authorized_keys")
        return nil
      end

      authorized_keys_file.gsub!(/%h/, account_info.dir)
    end

    # If relative path, use the homedir.
    if authorized_keys_file[0] != "/"
      if account_info == nil
        @logger.warn("No homedirectory for #{@account} and authorized_keys path is relative, skipping authorized_keys")
        return nil
      end

      authorized_keys_file = "#{account_info.dir}/#{authorized_keys_file}"
    end

    return authorized_keys_file
  end # find_authorized_keys_file

  def authorized_keys
    if @authorized_keys_file
      authorized_keys_file = @authorized_keys_file
    else
      authorized_keys_file = find_authorized_keys_file
    end

    if authorized_keys_file == nil
      @logger.info("No authorized keys file found.")
      return []
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
      @logger.info line

      comment = nil

      # TODO(sissel): support more known_hosts formats
      if line =~ /^\|1\|/ # hashed known_hosts format
        comment, line = line.split(" ",2)
      end

      identity = Net::SSH::KeyFactory.load_data_public_key(line)

      # Add the '.comment' attribute to our key
      identity.extend(Net::SSH::Authentication::Agent::Comment)

      match = AUTHORIZED_KEYS_REGEX.match(line)
      if match
        comment = match[-1] 
      else
        puts "No comment or could not parse #{line}"
      end
      identity.comment = comment if comment

      keys << identity
    end
    return keys
  end

  # Add a private key to this Verifier from a file (like ".ssh/id_rsa")
  # * path - the string path to the key
  # * passphrase - the passphrase for this key, omit if no passphrase.
  def add_private_key_file(path, passphrase=nil)
    @keys << Net::SSH::KeyFactory.load_private_key(path, passphrase)
  end # def add_private_key_file(path)

  # Add a public  key to this Verifier from a file (like ".ssh/id_rsa.pub")
  #
  # This is for individual key files. If you want to specify an alternate
  # location for your authorized_keys file, set:
  #   Verifier#authorized_keys_file = "/path/to/authorized_keys"
  #
  # * path - the string path to the public key
  def add_public_key_file(path)
    @keys << Net::SSH::KeyFactory.load_public_key(path)
  end # def add_private_key_file(path)
end; end; end # class SSH::Key::Verifier
