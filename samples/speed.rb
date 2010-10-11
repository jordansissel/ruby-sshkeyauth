#!/usr/bin/env ruby
#

require "base64"
require "json"
$:.unshift "../lib"
$:.unshift "lib"
require "ssh/key/signer"

data = (argv[0] or "Hello world")
signer = SSH::Key::Signer.new

start = Time.now
0.upto(1000) do 
  sigs = signer.sign(data)
end
duration = Time.now - start
puts "Duration: #{duration}"
