# ipspatcherFuzzer

A description of this package.

    swift package init --type=executable
    swift build -c release -Xswiftc -sanitize=fuzzer,address -Xswiftc -parse-as-library
    ./.build/x86_64-apple-macosx/release/ipspatcherFuzzer
