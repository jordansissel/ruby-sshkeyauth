require "ssh-agent"
require "ap"
agent = SSHAgent.new

data = "hello"
sigs = agent.sign(data)
sigs.each do |identity, sig|
  ap agent.verify(sig, data)
end

