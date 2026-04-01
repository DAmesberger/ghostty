# Build optimization: "ReleaseFast" (default) or "Debug"
optimize := "ReleaseFast"

# Build the ghostty daemon
daemon:
    zig build -Dapp-runtime=none -Demit-daemon=true -Demit-docs=false -Demit-xcframework=false -Doptimize={{optimize}} -Dcpu=baseline

# Build the full ghostty macOS app (two-stage: zig lib + xcodebuild)
ghostty:
    zig build -Demit-macos-app=false -Doptimize={{optimize}} -Dcpu=baseline
    env -i HOME="$HOME" PATH="/usr/bin:/bin:/usr/sbin:/sbin" DEVELOPER_DIR="$(xcode-select -p)" xcodebuild -project macos/Ghostty.xcodeproj -target Ghostty -configuration ReleaseLocal

# Build both
all: daemon ghostty

# Clean build artifacts
clean:
    rm -rf .zig-cache zig-out macos/build
