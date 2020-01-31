# ipspatcherFuzzer

This is a toy program that's used to demonstrate how to fuzz test your Swift libraries.  The main source is a fuzzer for the [ipspatcher library][lib].

You may find more information about the project, its purpose, and how fuzzing in Swift works in the [docs][] or in a [prettier format][io].

[lib]: https://github.com/Grayson/ipspatcher
[docs]: blob/master/docs/index.md
[io]: https://grayson.github.io/ipspatcherFuzzer/

## How to compile and run

This program requires Swift 5.2+ from [swift.org's downloads page][dl].  You can also manage the version of Swift that you use with [swiftenv][env].  The version of Swift that comes with Xcode does not support fuzz testing.

[dl]: https://swift.org/download/
[env]: https://swiftenv.fuller.li/en/latest/

You can can build the fuzzer program by opening your shell and navigating to the root of this repo.  The following command builds the fuzzer with the proper instrumentation:

    swift build -c release -Xswiftc -sanitize=fuzzer,address -Xswiftc -parse-as-library

Once successfully built, you'll have a hidden folder called ".build" in the root of the repo.  You can locate and run the fuzzer with the following command:

    ./.build/x86_64-apple-macosx/release/ipspatcherFuzzer

## Contact information

If you have any suggestions, improvements, or comments, please feel free to create an Issue or contact me by [email][] or on [Twitter][].

[email]: mailto:grayson.hansard@gmail.com
[Twitter]: http://twitter.com/Grayson
