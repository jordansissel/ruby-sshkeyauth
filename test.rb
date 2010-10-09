require "lib/ssh/key/signer"
require "lib/ssh/key/verifier"
require "ap"
require "etc"

signer = SSH::Key::Signer.new
verifier = SSH::Key::Verifier.new

data = "hello"
sigs = signer.sign(data)

ap verifier.verify(signs)
#sigs.each do |identity, sig|
  #if agent.verify?(sig, data)
    #puts "Verified: #{identity.comment}"
  #end
#end # sigs.each

