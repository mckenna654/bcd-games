# bcd-games (BCD / Madeira) — agent instructions

Jake's fork of `thebcd69/bcd-games`: runs Windows games on iOS/iPadOS (Wine + FEX + DXMT + a D3D12
runtime, Swift app in `app/Madeira.xcodeproj`). Global rules: `mckenna654/agent-config`.

## Building
- Cloud sessions are Linux: edit and review there, but the IPA builds on macOS only, either through
  `.github/workflows/build-ipa.yml` (`workflow_dispatch`, newest Xcode, iOS 26 SDK) or on Jake's Mac
  with the `docs/local-build` scripts.
- The build number comes from `docs/local-build/BUILD-NUMBER`, one sequence shared by CI and the
  Mac. Commit a bump as `Build N (...)` before dispatching a build. Never use GitHub's run number.
- `.githooks/pre-push` runs checks. Enable it with `git config core.hooksPath .githooks`.

## Rules
- Licence: GPL-3.0-or-later with the Madeira Converter Exception. Sign off every commit (`git commit -s`).
- Submodules (`wine`, `FEX`, `dxmt`, `madeira-dock`) point to `thebcd69/*`. Change them in their own
  repos, then bump the submodule pointer here.
- **FEX-Emu forbids AI-generated code.** Do not write code intended for FEX upstream.
- Never commit signing certificates, provisioning profiles, Steam/GOG credentials or game files.
- Do not claim a game runs unless it was tested on a device. Say which build and device.
