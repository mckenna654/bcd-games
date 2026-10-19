# Shared executable sections for x64 guests

Diablo II: Resurrected creates two views of a pagefile section, writes through one
and executes through the other. BCD 573's device log shows the executable view
copied into the JIT pool while zero-filled, and both emulator notifications
skipped because the mapping has no loader filename. FEX later reports NoExec and
D2R_loader.dll initialization terminates with c0000005. See issue #3.

The native memory change keeps eligible x64 section views on their original shared
backing. Wine retains logical execute permission, while the host treats the guest
instruction bytes as readable data. ARM64EC native code, system mappings, images,
ordinary file mappings and 32-bit guest windows keep their existing paths.

The Wine companion change notifies the emulator about actual committed-region
protections for non-image sections before the loader-filename gate. It uses the
existing syscall guard and protection callbacks, skips reserved holes, and serves
both section-map variants. Non-image sections never reach the PE image parser.
Both changes are required: byte sharing and emulator executable-range tracking
are independent requirements.

## Build

Rebuild both the native library and ARM64EC PE ntdll. Updating the Wine revision
without updating the bundled ntdll.dll leaves the notification fix out of the IPA.
The PE runtime can be built with build/wine-pe/build-ntdll.sh in a configured Wine
ARM64EC build tree. Its PE-only make target avoids linking the unrelated desktop
ntdll.so. The dependency build lists include Wine sfc, sfc_os and tbs, which the
D2R loader imports.

## Validation

Host tests: python3 tests/host/check-guest-section.py and the existing
check-x64-image-nocopy.py. The section test compiles extracted production helpers
with address/undefined-behavior sanitizers; it does not emulate FEX.

Compile tests/x64/shared-section-x64.c with x86_64-w64-mingw32-clang -O2 -Wall
-Wextra -Werror. Launch the resulting executable in a fresh BCD session. Expect
four PASS lines and shared-section: PASS, then exit code zero. The cases cover
initial shared write/execution, rewrite plus instruction-cache flush, protection
transitions, and unmap/remap. Run D2R in a separate fresh BCD session through Dock
and capture the per-game log. Also smoke-test a working 64-bit and 32-bit game.

The same narrow test passed on this iPhone using an earlier Madeira build. This
BCD port requires its own device validation. D2R progressed further in that
Madeira build but later hung; this change does not establish full compatibility.
The test explicitly flushes the executable address after rewriting its sibling;
automatic invalidation for arbitrary cross-alias writes is not established.

No FEX source change is included. The experimental exception-callback retry from
the later Madeira investigation is not part of this change.
