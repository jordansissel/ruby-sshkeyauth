$:.unshift "../lib"
require "ssh/key/signer"
require "ssh/key/verifier"


signer = SSH::Key::Signer.new
verifier = SSH::Key::Verifier.new

original = "Hello world"
result = signer.sign original
verified = verifier.verify?(result, original)
puts "Verified: #{verified}" 

