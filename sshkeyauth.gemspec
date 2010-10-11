Gem::Specification.new do |spec|
  files = []
  #dirs = %w{lib samples test bin}
  dirs = %w{lib samples}
  dirs.each do |dir|
    files += Dir["#{dir}/**/*"]
  end

  #svnrev = %x{svn info}.split("\n").grep(/Revision:/).first.split(" ").last.to_i
  rev = Time.now.strftime("%Y%m%d%H%M%S")
  spec.name = "sshkeyauth"
  spec.version = "0.0.4"
  spec.summary = "ssh key authentication (signing and verification)"
  spec.description = "Use your ssh keys (and your ssh agent) to sign and verify messages"
  spec.add_dependency("net-ssh")
  spec.files = files
  spec.require_paths << "lib"

  spec.author = "Jordan Sissel"
  spec.email = "jls@semicomplete.com"
  spec.homepage = "http://github.com/jordansissel/ruby-sshkeyauth"
end
