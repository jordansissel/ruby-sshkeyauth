# TODO(sissel): Cache keys read from disk?
#
class Signatur
  attr_reader :type
  attr_reader :signature
  attr_accessor :identity


  def initialize
    @use_agent = true
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
