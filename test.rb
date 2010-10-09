require "lib/ssh/key/signer"
require "lib/ssh/key/verifier"
require "ap"
require "etc"

signer = SSH::Key::Signer.new
verifier = SSH::Key::Verifier.new

data = "hello"
sigs = signer.sign(data)

# Should succeed
print "Verified: %s" % verifier.verify(signs, data)

# Should fail
print "Verified: %s" % verifier.verify(signs, "foobar#{data}")

