
require "test/unit"

$:.unshift "#{File.dirname(__FILE__)}/../lib"
require "ssh/key/signer"
require "ssh/key/verifier"

class TestAgent < Test::Unit::TestCase
  def setup
    # Ensure we don't accidentally use the caller's ssh agent
    ENV.delete("SSH_AUTH_SOCK")
    ENV.delete("SSH_AGENT_PID")

    # Run our own ssh-agent; it will output values and then fork/detach
    values = %x{ssh-agent}.split("\n").grep(/^SSH[^=]+=/)
    values.collect { |line| line.split("=", 2) }.each do |key, value|
      value.gsub!(/; export.*/, "")
      ENV[key] = value
      #puts "ENV[#{key}] = #{value}"
    end
  end # def setup

  def teardown
    # Should we use ssh-agent -k, instead?
    Process.kill("KILL", ENV["SSH_AGENT_PID"].to_i) rescue nil
  end # def teardown

  def test_no_keys
    signer = SSH::Key::Signer.new
    idcount = signer.signing_identities.length
    assert_equal(0, idcount,
                 "A new signer with an empty ssh-agent should have no " \
                 "identities, found #{idcount}")
  end

  def test_with_rsa_key
    system("ssh-add keys/tester_nopassphrase_rsa > /dev/null 2>&1")

    signer = SSH::Key::Signer.new
    idcount = signer.signing_identities.length
    assert_equal(1, idcount, "Expected 1 identity, found #{idcount}.")
  end

  def test_sign_and_verify_with_rsa_key
    system("ssh-add keys/tester_nopassphrase_rsa > /dev/null 2>&1")
    signer = SSH::Key::Signer.new
    verifier = SSH::Key::Verifier.new

    inputs = [ "hello", "foo bar 1 2 3 4", Marshal.dump({:test => :fizz}),
               "", "1", " " ]
    inputs.each do |data|
      signatures = signer.sign(data)
      assert(verifier.verify?(signatures, data),
             "Signature verify failed against data '#{data.inspect}'")
    end
  end

  def test_sign_and_verify_with_rsa_key_fails_on_bad_data
    system("ssh-add keys/tester_nopassphrase_rsa > /dev/null 2>&1")
    signer = SSH::Key::Signer.new
    verifier = SSH::Key::Verifier.new

    inputs = [ "hello", "foo bar 1 2 3 4", Marshal.dump({:test => :fizz}),
               "", "1", " " ]
    inputs.each do |data|
      signatures = signer.sign(data)
      assert(!verifier.verify?(signatures, data + "bad"),
             "Signature verify expected to fail when verifying against altered data")
    end
  end
end # class TestAgent


