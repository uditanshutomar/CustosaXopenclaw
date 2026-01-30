# Homebrew Cask Template

Copy `Casks/custosa.rb` into your Homebrew tap repo and update:

- `version`
- `sha256`
- `url`

Release flow (example):

1) Build the app bundle:

   ./scripts/build_macos.sh

2) Package the DMG:

   ./scripts/package_dmg.sh

3) Rename the DMG (if needed):

   mv dist/Custosa.dmg dist/CustosaXopenclaw.dmg

4) Create a GitHub release and upload the DMG to the release tag.

5) Compute checksum:

   shasum -a 256 dist/CustosaXopenclaw.dmg

6) Update the cask in your tap (version + sha256) and commit/tag the release.
