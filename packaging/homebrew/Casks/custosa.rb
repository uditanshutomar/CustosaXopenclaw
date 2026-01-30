cask "custosa" do
  version "1.0.0"
  sha256 "954a2fa70a3009a6cad323cad6b6765693bfcd79d1706faf1ceedf2739fa31d8"

  url "https://github.com/uditanshutomar/CustosaXopenclaw/releases/download/#{version}/CustosaXopenclaw.zip"
  name "Custosa"
  desc "Prompt Injection Protection for OpenClaw/Moltbot"
  homepage "https://github.com/custosa/custosa"

  depends_on macos: ">= :ventura"

  app "Custosa.app"

  uninstall launchctl: "com.custosa.proxy"
  zap trash: [
    "~/Library/LaunchAgents/com.custosa.proxy.plist",
    "~/.custosa",
  ]
end
