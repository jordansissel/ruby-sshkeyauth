#!/usr/bin/env ruby
#

require "base64"
require "json"
$:.unshift "../lib"
require "ssh/key/signer"

def main(argv)
  if argv.length == 0
    data = $stdin.read
  else
    data = argv[0]
  end
  signer = SSH::Key::Signer.new
  sigs = signer.sign(data)
  sigs.each do |identity, signature|
    sig64 = Base64.encode64(signature.signature)
    puts({ "original" => data, "signature" => sig64 }.to_json)
  end
end

main(ARGV)
