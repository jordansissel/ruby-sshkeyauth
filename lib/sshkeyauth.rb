#!/usr/bin/env ruby

require "rubygems"
require "net/ssh"

class SSHKeySignature
  attr_reader :type
  attr_reader :signature
  attr_reader :identity

  def initialize(account)
    @use_agent = true
    @account = account
  end

  def self.from_string(string)
    keysig = SSHKeySignature.new
    keysig.parse(string)
    return keysig
  end

  # Parse an ssh key signature. Expects a signed string that came from the ssh
  # agent, such as from SSHKeyAuth#sign
  def parse(string)
    offset = 0
    typelen = string[offset..(offset + 3)].reverse.unpack("L")[0]
    offset += 4
    @type = string[offset .. (offset + typelen)]
    offset += typelen
    siglen = string[offset ..(offset + 3)].reverse.unpack("L")[0]
    offset += 4
    @signature = string[offset ..(offset + siglen)]
  end # def parse
end

class SSHKeyAuth
  def initialize
    @agent = Net::SSH::Authentication::Agent.new
    @use_agent = true
  end # def initialize

  def ensure_connected
    begin
      @agent.connect! if !@agent.socket
    rescue Net::SSH::Authentication::AgentNotAvailable => e
      @use_agent = false
    end
  end # def ensure_connected

  def sign(string)
    ensure_connected
    identities = signing_identities 
    signatures = {}
    identities.each do |identity|
      signatures[identity] = SSHKeySignature.from_string(@agent.sign(identity, string))
    end
    return signatures
  end

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
    return @agent.identities
  end # def signing_identities

  def verifying_identities
    identities = []
    @agent.identities.each { |id| identities << id }

    if ENV.include?("HOME") and File.exists?("#{ENV["HOME"]}/.ssh/authorized_keys

  end
end # class SSHKeyAuth

