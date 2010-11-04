
require "test/unit"

$:.unshift "#{File.dirname(__FILE__)}/../lib"
require "ssh/key/signer"
require "ssh/key/verifier"

class TestWithFiles < Test::Unit::TestCase
  def setup
    @signer = SSH::Key::Signer.new
    @signer.use_agent = false

    @verifier = SSH::Key::Verifier.new
    @verifier.use_agent = false
    @verifier.use_authorized_keys = false
  end # def setup

  def test_with_rsa_key_without_passphrase
    @signer.add_private_key_file("keys/tester_nopassphrase_rsa")
    idcount = @signer.signing_identities.length
    assert_equal(1, idcount, "Expected 1 identity, found #{idcount}.")
  end # def test_with_rsa_key_without_passphrase

  def test_with_rsa_key_with_passphrase
    @signer.add_private_key_file("keys/tester_withpassphrase_rsa", "testing")
    idcount = @signer.signing_identities.length
    assert_equal(1, idcount, "Expected 1 identity, found #{idcount}.")
  end

  def test_sign_and_verify_with_rsa_key_file
    @signer.add_private_key_file("keys/tester_nopassphrase_rsa")
    @verifier.add_public_key_file("keys/tester_nopassphrase_rsa.pub")

    inputs = [ "hello", "foo bar 1 2 3 4", Marshal.dump({:test => :fizz}),
               "", "1", " " ]
    inputs.each do |data|
      signatures = @signer.sign(data)
      assert(@verifier.verify?(signatures, data),
             "Signature verify failed against data '#{data.inspect}'")
    end
  end

  def test_sign_and_verify_with_rsa_key_fails_on_bad_data
    @signer.add_private_key_file("keys/tester_nopassphrase_rsa")
    @verifier.add_public_key_file("keys/tester_nopassphrase_rsa.pub")

    inputs = [ "hello", "foo bar 1 2 3 4", Marshal.dump({:test => :fizz}),
               "", "1", " " ]
    inputs.each do |data|
      signatures = @signer.sign(data)
      assert(!@verifier.verify?(signatures, data + "bad"),
             "Signature verify expected to fail when verifying against altered data")
    end
  end
end # class TestWithFiles
