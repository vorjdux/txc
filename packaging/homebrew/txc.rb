# Homebrew formula for txc, installing the released binary rather than
# building from source: the release already carries a signed, checksummed
# archive for both macOS architectures.
#
# The version and checksums are filled in by packaging/render.sh during a
# release. Publish the rendered file to a tap, for example
# vorjdux/homebrew-tap, as Formula/txc.rb.
class Txc < Formula
  desc "Offline text utilities for the terminal"
  homepage "https://github.com/vorjdux/txc"
  version "@VERSION@"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/vorjdux/txc/releases/download/v@VERSION@/txc-@VERSION@-macos-arm64.tar.gz"
      sha256 "@SHA256_MACOS_ARM64@"
    end
    on_intel do
      url "https://github.com/vorjdux/txc/releases/download/v@VERSION@/txc-@VERSION@-macos-x86_64.tar.gz"
      sha256 "@SHA256_MACOS_X86_64@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vorjdux/txc/releases/download/v@VERSION@/txc-@VERSION@-linux-aarch64.tar.gz"
      sha256 "@SHA256_LINUX_AARCH64@"
    end
    on_intel do
      url "https://github.com/vorjdux/txc/releases/download/v@VERSION@/txc-@VERSION@-linux-x86_64.tar.gz"
      sha256 "@SHA256_LINUX_X86_64@"
    end
  end

  def install
    bin.install "txc"
    bash_completion.install "completions/txc.bash" => "txc"
    zsh_completion.install "completions/_txc"
    fish_completion.install "completions/txc.fish"
    doc.install "README.md"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/txc --version")
    assert_equal "SEVOLG", shell_output("#{bin}/txc upper gloves").chomp.reverse
  end
end
