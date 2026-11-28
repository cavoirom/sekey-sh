class SekeySh < Formula
  desc "Manage SSH keypairs stored in Apple Secure Enclave"
  homepage "https://github.com/cavoirom/sekey-sh"
  url "https://github.com/cavoirom/sekey-sh/archive/refs/tags/0.1.1.tar.gz"
  sha256 "0b380947827ff2029ef28246ba4ffeb080b5ddc29925beb55f65dc278e1cd83e"
  license "Unlicense"

  depends_on macos: :tahoe

  def install
    bin.install "sekey.sh"
  end

  def caveats
    <<~EOS
      After creating keypairs, run 'sekey.sh -a' to add them to ssh-agent.
      Do not run sekey.sh with sudo.
    EOS
  end

  test do
    assert_equal "sekey.sh #{version}", shell_output("#{bin}/sekey.sh --version").chomp
  end
end
