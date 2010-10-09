require "lib/sshkeyauth"
require "ap"
require "etc"

agent = SSHKeyAuth.new(Etc.getlogin)

data = "hello"
sigs = agent.sign(data)

sigs.each do |identity, sig|
  if agent.verify?(sig, data)
    puts "Verified: #{identity.comment}"
  end
end # sigs.each

