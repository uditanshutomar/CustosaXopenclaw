# Homebrew Cask Template

Copy `Casks/custosa.rb` into your Homebrew tap repo and update:

- `version`
- `sha256`
- `url`

Release flow (example):

1) Build the app bundle:

   ./scripts/build_macos.sh

2) Package the ZIP:

   ./scripts/package_zip.sh

3) Create a GitHub release and upload the ZIP to the release tag.

4) Compute checksum:

   shasum -a 256 dist/CustosaXopenclaw.zip

5) Update the cask in your tap (version + sha256) and commit/tag the release.
