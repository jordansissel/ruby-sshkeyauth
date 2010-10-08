#!/usr/bin/env ruby

require "rubygems"
require "net/ssh"

class SSHKeySignature
  attr_reader :type
  attr_reader :signature
  attr_reader :identity

  def initialize
  end

  def self.from_string(string)
    keysig = SSHKeySignature.new
    keysig.parse(string)
    return keysig
  end

  # Parse an ssh key signature. Expects a signed string that came from the ssh
  # agent, such as from SSHAgent#sign
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

class SSHAgent
  def initialize
    @agent = Net::SSH::Authentication::Agent.new
  end # def initialize

  def ensure_connected
    @agent.connect! if !@agent.socket
  end # def ensure_connected

  def sign(string)
    ensure_connected
    identities = @agent.identities
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
    identities = @agent.identities
    results = {}
    identities.each do |identity|
      results[identity] = identity.ssh_do_verify(signature, original)
    end
    return results
  end
end # class SSHAgent

