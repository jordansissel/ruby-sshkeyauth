#!/usr/bin/env ruby

require "rubygems"
require "net/ssh"
require "ssh/key/signature"
require "etc"

module SSH; module Key; class Signer
  attr_accessor :account
  attr_accessor :sshd_config_file
  attr_accessor :logger

  def initialize
    @agent = ::Net::SSH::Authentication::Agent.new
    @use_agent = true
    @logger = Logger.new(STDERR)
    @logger.level = Logger::WARN
  end # def initialize

  def ensure_connected
    begin
      @agent.connect! if !@agent.socket
    rescue ::Net::SSH::Authentication::AgentNotAvailable => e
      @use_agent = false
    end
  end # def ensure_connected

  # Signs a string with all available ssh keys
  #
  # * string - the value to sign
  #
  # Returns a hash of { identity => signature } mapping. 
  #
  # 'identity' is an openssl key instance of one of these typs: 
  # * OpenSSL::PKey::RSA
  # * OpenSSL::PKey::DSA
  # * OpenSSL::PKey::DH
  #
  # Net::SSH monkeypatches these classes to add additional methods, so
  # just be aware.
  #
  #'signature' is an SSH::Key::Signature instance.
  def sign(string)
    ensure_connected
    identities = signing_identities 
    signatures = {}
    identities.each do |identity|
      signatures[identity] = SSH::Key::Signature.from_string(@agent.sign(identity, string))
      signatures[identity].identity = identity
    end
    return signatures
  end

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

  def signing_identities
    ensure_connected
    return @agent.identities
  end # def signing_identities
end; end; end # class SSH::Key::Signer
