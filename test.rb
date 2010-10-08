require "lib/sshkeyauth"
require "ap"
agent = SSHKeyAuth.new

data = "hello"
sigs = agent.sign(data)



sigs.each do |identity, sig|
  ap agent.verify(sig, data)
end

