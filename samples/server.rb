#!/usr/bin/env ruby
#

require "base64"
require "json"
$:.unshift "../lib"
require "ssh/key/verifier"

def main(argv)
  if argv.length == 0
    input = $stdin
  else
    input = argv
  end
  verifier = SSH::Key::Verifier.new

  input.each do |line|
    data = JSON.parse(line)
    signature = Base64.decode64(data["signature"])
    original = data["original"]
    puts verifier.verify?(signature, original)
  end
end

main(ARGV)
