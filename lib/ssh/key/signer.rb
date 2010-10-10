#!/usr/bin/env ruby

require "rubygems"
require "net/ssh"
require "ssh/key/signature"
require "etc"

module SSH; module Key; class Signer
  attr_accessor :account
  attr_accessor :sshd_config_file
  attr_accessor :logger
  attr_accessor :use_agent

  def initialize
    @agent = Net::SSH::Authentication::Agent.new
    @use_agent = true
    #@logger = Logger.new(STDERR)
    #@logger.level = Logger::WARN
    @logger = Logger.new("/tmp/verifier.log")
    @logger.level = Logger::INFO
    @keys = []
  end # def initialize

  def ensure_connected
    begin
      @agent.connect! if !@agent.socket
    rescue Net::SSH::Authentication::AgentNotAvailable => e
      @use_agent = false
    end
  end # def ensure_connected

  # Add a private key to this signer.
  def add_key_file(path, passphrase=nil)
    @logger.info "Adding key from file #{path} (with#{passphrase ? "" : "out"} passphrase)"
    @keys << Net::SSH::KeyFactory.load_private_key(path, passphrase)
  end # def add_key_file

  # Signs a string with all available ssh keys
  #
  # * string - the value to sign
  #
  # Returns an array of SSH::Key::Signature objects
  #
  # 'identity' on each object is an openssl key instance of one of these typs:
  # * OpenSSL::PKey::RSA
  # * OpenSSL::PKey::DSA
  # * OpenSSL::PKey::DH
  #
  # Net::SSH monkeypatches the above classes to add additional methods, so just
  # be aware.
  def sign(string)
    identities = signing_identities 
    signatures = []
    identities.each do |identity|
      if identity.private?
        # FYI: OpenSSL::PKey::RSA#ssh_type and #ssh_do_sign are monkeypatched
        # by Net::SSH
        signature = SSH::Key::Signature.new
        signature.type = identity.ssh_type
        signature.signature = identity.ssh_do_sign(string)
      else
        # Only public signing identities come from our agent.
        signature = SSH::Key::Signature.from_string(@agent.sign(identity, string))
      end
      signature.identity = identity
      signatures << signature
    end
    return signatures
  end

  def signing_identities
    identities = []
    if @use_agent
      ensure_connected
      begin
        @agent.identities.each { |id| identities << id }
      rescue => e
        @logger.warn("Error talking to agent while asking for message signing. Disabling agent (Error: #{e})")
        @use_agent = false
      end
    end

    if @keys
      @keys.each { |id| identities << id }
    end
    return identities
  end # def signing_identities
end; end; end # class SSH::Key::Signer
