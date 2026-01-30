cask "custosa" do
  version "1.0.4"
  sha256 "77db276e97ead302a52f04125966bdd075afe4848c0a0d18cff2ae9407b03b85"

  url "https://github.com/uditanshutomar/CustosaXopenclaw/releases/download/#{version}/CustosaXopenclaw.zip"
  name "Custosa"
  desc "Prompt Injection Protection for OpenClaw/Moltbot"
  homepage "https://github.com/custosa/custosa"

  depends_on macos: ">= :ventura"

  app "Custosa.app"

  postflight do
    system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{appdir}/Custosa.app"]
    system_command "/bin/sh", args: ["-c", "/usr/bin/open -a Custosa >/dev/null 2>&1 &"], sudo: false
  end

  uninstall launchctl: "com.custosa.proxy"
  zap trash: [
    "~/Library/LaunchAgents/com.custosa.proxy.plist",
    "~/.custosa",
  ]
end
