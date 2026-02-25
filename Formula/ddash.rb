class Ddash < Formula
  desc "Lightweight process sandboxing for macOS"
  homepage "https://github.com/marklechner/ddash"
  url "https://github.com/marklechner/ddash/archive/refs/tags/v0.1.1.tar.gz"
  sha256 "54afa28c36115205fc38b86b9d56af0ff058e73afba98a01294b634c3552eeef"
  license "MIT"

  depends_on "go" => :build
  depends_on :macos

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X github.com/marklechner/ddash/cmd.Version=#{version}")
  end

  test do
    assert_match "ddash version #{version}", shell_output("#{bin}/ddash version")

    # Test sandbox init creates config
    system bin/"ddash", "sandbox", "init"
    assert_path_exists testpath/".ddash.json"

    # Test profile generation
    output = shell_output("#{bin}/ddash run --profile -- echo test")
    assert_match "(deny default)", output
  end
end
