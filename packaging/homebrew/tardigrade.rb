# Homebrew formula for Tardigrade.
#
# Usage (from a local tap or --formula flag):
#   brew install --formula packaging/homebrew/tardigrade.rb
#
# To publish via a tap:
#   Create a repo named homebrew-tap under Bare-Systems/homebrew-tap,
#   copy this formula to Formula/tardigrade.rb, and users can install with:
#     brew tap Bare-Systems/tap
#     brew install tardigrade
#
# The sha256 values below must be updated on each release.
# Run: sha256sum tardigrade-darwin-*.tar.gz

class Tardigrade < Formula
  desc "High-performance Zig edge gateway: TLS termination, reverse proxy, realtime transport"
  homepage "https://github.com/Bare-Systems/Tardigrade"
  version "0.50"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/Bare-Systems/Tardigrade/releases/download/v#{version}/tardigrade-darwin-arm64.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_FOR_DARWIN_ARM64"
    end
    on_intel do
      url "https://github.com/Bare-Systems/Tardigrade/releases/download/v#{version}/tardigrade-darwin-x86_64.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_FOR_DARWIN_X86_64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Bare-Systems/Tardigrade/releases/download/v#{version}/tardigrade-linux-aarch64.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_FOR_LINUX_AARCH64"
    end
    on_intel do
      url "https://github.com/Bare-Systems/Tardigrade/releases/download/v#{version}/tardigrade-linux-x86_64.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_FOR_LINUX_X86_64"
    end
  end

  def install
    bin.install "tardigrade"
  end

  service do
    run [opt_bin/"tardigrade"]
    keep_alive true
    log_path var/"log/tardigrade.log"
    error_log_path var/"log/tardigrade.log"
    environment_variables TARDIGRADE_LISTEN_PORT: "8069"
  end

  test do
    pid = fork do
      exec bin/"tardigrade", "--version"
    end
    Process.wait pid
    assert_equal 0, $CHILD_STATUS.exitstatus
  end
end
