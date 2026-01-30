cask "custosa" do
  version "1.0.6"
  sha256 "69315e37bf71e74b3f3551cb75b38a7e3c3dc0266169a17e83cfbe47c297de96"

  url "https://github.com/uditanshutomar/CustosaXopenclaw/releases/download/#{version}/CustosaXopenclaw.zip"
  name "Custosa"
  desc "Prompt Injection Protection for OpenClaw/Moltbot"
  homepage "https://github.com/custosa/custosa"

  depends_on macos: ">= :ventura"

  app "Custosa.app"

  postflight do
    system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{appdir}/Custosa.app"]
    system_command "/usr/bin/open", args: ["-a", "Custosa"], must_succeed: false
    console_uid = File.stat("/dev/console").uid
    system_command "/bin/launchctl",
                   args: ["asuser", console_uid.to_s, "/usr/bin/open", "-a", "Custosa"],
                   sudo: true,
                   must_succeed: false
  end

  uninstall launchctl: "com.custosa.proxy"
  zap trash: [
    "~/Library/LaunchAgents/com.custosa.proxy.plist",
    "~/.custosa",
  ]
end
