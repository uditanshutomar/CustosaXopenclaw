cask "custosa" do
  version "1.0.3"
  sha256 "5d29c882706e7420a33aeb87613d25c69cc742e4d992b5d4079d764cad70b26a"

  url "https://github.com/uditanshutomar/CustosaXopenclaw/releases/download/#{version}/CustosaXopenclaw.zip"
  name "Custosa"
  desc "Prompt Injection Protection for OpenClaw/Moltbot"
  homepage "https://github.com/custosa/custosa"

  depends_on macos: ">= :ventura"

  app "Custosa.app"

  postflight do
    system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{appdir}/Custosa.app"]
    system_command "/usr/bin/open", args: ["-a", "Custosa"], sudo: false
  end

  uninstall launchctl: "com.custosa.proxy"
  zap trash: [
    "~/Library/LaunchAgents/com.custosa.proxy.plist",
    "~/.custosa",
  ]
end
