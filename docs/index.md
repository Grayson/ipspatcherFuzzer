# Fuzz Testing with Swift

The official Swift documentation on [using LLVM's libFuzzer with Swift][1] is a little thin on details.  I wanted to learn more about fuzz testing and share what I've recently learned, so my findings have been recorded in this document and some related projects.

You may want to grab [FuzzerInterface][2] and [ipspatcher][3], but they're not necessary to actually follow along.  Swift's package system will also grab them automatically if you do wind up running the ipspatcherFuzzer, so it's not necessary to download them to have them installed anywhere just to get started.

[1]: https://github.com/apple/swift/blob/master/docs/libFuzzerIntegration.rst
[2]: https://github.com/Grayson/FuzzerInterface
[3]: https://github.com/Grayson/ipspatcher

## What is Fuzz Testing?

[Fuzz testing][4] is a kind of automated testing.  It's different from other tests in that it doesn't really provide confidence that code is *working*.  Unlike unit testing, it doesn't verify that your code meets some pre-defined expectation.  Instead, it's a way to increase confidence in the robustness of your code by hammering it with randomness.  Because libFuzzer is integrated into LLVM, the Swift compiler can add instrumentation to help guide the fuzziness to cover as many sections of your code as possible.

[4]: https://en.wikipedia.org/wiki/Fuzzing

## What is an IPS Patch

The IPS Patch file format is a very simple file format that contains a few things.  It contains a header ("PATCH"), a footer ("EOF"), and several "hunks".  A Hunk is a blob of bytes that begin with three bytes for an address space, follows with two bytes to indicate the length of the following data, and one or more bytes as a payload.  During a patch, the patcher will locate the address within a file from the one specified by the hunk, and then insert the payload at that location.

Patching wasn't actually implemented and it isn't really interesting to fuzz testing.  It was just an arbitrary choice for a data format that was simple enough to understand and implement quickly but providing enough complexity to demonstrate fuzzing.

## Setup

This project was set up in the following way:

1. The ipspatcher library was created using `swift package init` and implemented using standard development practices (complete with some unit tests).
2. The fuzzer program was created using `swift package init --type=executable`.
3. The FuzzerInterface repo was created to provide symbols for the fuzzer program.
4. The fuzzer [has dependencies][dep] on the library and the interface symbols repo.
5. The fuzzer program target [has a dependency][dep2] on the library.
6. At various times, you may be asked to change the version of the library dependency in order to demonstrate the fuzzer in action.

[dep]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Package.swift#L9-L10
[dep2]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Package.swift#L15

## FuzzerInterface

The FuzzerInterface repo exists merely to provide some symbols to Swift for the fuzzer to use.  It exposes a [header file][header].  Fuzzer applications will implement `LLVMFuzzerTestOneInput` and potentially `LLVMFuzzerCustomMutator`, so the only symbol that's actually needed is `LLVMFuzzerMutate` (which is a function you can call in your custom mutator).  The actual implementation of `LLVMFuzzerMutate` will be provided by the compiler during the linking phase.

[header]: https://github.com/Grayson/FuzzerInterface/blob/master/FuzzerInterface.h

## The Bug

There's a bug in the [initial commit][ic] of Hunk.swift.  It's subtle but will cause a crash.  Here's the thing: Hunk is unit tested.  Kinda.  Not thoroughly enough, obviously.  But it's *entirely* possible to have 100% code coverage in unit tests and still miss these bugs.

I'm not going to spoil the surprise.  Kudos to you if you've already spotted it.  We'll now see how a fuzzer can help us find the problem.

[ic]: https://github.com/Grayson/ipspatcher/blob/00e840a048d1125dc385f38bca42f0e1b6b997f3/Sources/ipspatcher/Hunk.swift#L37-L45

## Fuzzing the Bug

Clone the [`ipspatcherFuzzer` repo][repo] if you haven't already.  Open Package.swift and change the `ipspatcher` dependency to "1.0.0" ([this line][line]).  Now, you'll need to build the fuzzer.  From the root of the repo, paste the following into the Terminal:

	swift build -c debug -Xswiftc -sanitize=fuzzer,address -Xswiftc -parse-as-library

That's not so bad.  It says to use the "debug" configuration, turn on the fuzzer and address sanitation instrumentations, and parse the file as a library.  libFuzzer implements it's own "main", so this just turns that off and lets LLVM do its thing.

You should now have a hidden `.build` folder.  You can run the fuzzer with:

	./.build/x86_64-apple-macosx/debug/ipspatcherFuzzer

In a very short time, the fuzzer will stop and print a lot of information.  There's also a beautiful stack trace to demonstrate exactly where the bug occurred.

	Fatal error: 
	==58689== ERROR: libFuzzer: deadly signal
		#0 0x10ccd46a5 in __sanitizer_print_stack_trace (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0x4e6a5)
		#1 0x10cc17898 in fuzzer::PrintStackTrace() (ipspatcherFuzzer:x86_64+0x10005b898)
		#2 0x10cbfc613 in fuzzer::Fuzzer::CrashCallback() (ipspatcherFuzzer:x86_64+0x100040613)
		#3 0x7fff6728242c in _sigtramp (libsystem_platform.dylib:x86_64+0x442c)
		#4 0xfffffffe  (ipspatcherFuzzer):x86_64+0xf3443ffe)
		#5 0x7fff666906ec in protocol witness for Collection._failEarlyRangeCheck(_:bounds:) in conformance UnsafeBufferPointer<A> (libswiftCore.dylib:x86_64+0x1a36ec)
		#6 0x7fff66656c23 in Slice.subscript.getter (libswiftCore.dylib:x86_64+0x169c23)
		#7 0x10cbce5b0 in static Hunk.from(slice:) Hunk.swift:42
		#8 0x10cbd77c9 in static Patch.from(pointer:length:) Patch.swift:29
		#9 0x10cbe0af2 in closure #1 in fuzz(data:size:) main.swift:44
		#10 0x10cbe1271 in thunk for @callee_guaranteed (@unowned UnsafePointer<UInt8>) -> (@error @owned Error) <compiler-generated>
		#11 0x10cbe12f1 in partial apply for thunk for @callee_guaranteed (@unowned UnsafePointer<UInt8>) -> (@error @owned Error) <compiler-generated>
		#12 0x7fff66618b6e in UnsafePointer.withMemoryRebound<A, B>(to:capacity:_:) (libswiftCore.dylib:x86_64+0x12bb6e)
		#13 0x10cbe032c in fuzz(data:size:) main.swift:43
		#14 0x10cbdf066 in LLVMFuzzerTestOneInput <compiler-generated>
		#15 0x10cbfdb90 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (ipspatcherFuzzer:x86_64+0x100041b90)
		#16 0x10cbfd3f5 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool*) (ipspatcherFuzzer:x86_64+0x1000413f5)
		#17 0x10cbff696 in fuzzer::Fuzzer::MutateAndTestOne() (ipspatcherFuzzer:x86_64+0x100043696)
		#18 0x10cc003a5 in fuzzer::Fuzzer::Loop(std::__1::vector<fuzzer::SizedFile, fuzzer::fuzzer_allocator<fuzzer::SizedFile> >&) (ipspatcherFuzzer:x86_64+0x1000443a5)
		#19 0x10cbeedb8 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (ipspatcherFuzzer:x86_64+0x100032db8)
		#20 0x10cc18bc2 in main (ipspatcherFuzzer:x86_64+0x10005cbc2)
		#21 0x7fff670897fc in start (libdyld.dylib:x86_64+0x1a7fc)

What's that?  `#7 0x10cbce5b0 in static Hunk.from(slice:) Hunk.swift:42` the fuzzer says?!  Why, it's the file and line number!  If we [take a look][hunk], we see that it's entirely possible that the payload length will go right past the end of the buffer if we get an incorrectly specified file.  With that knowledge, we can rapidly [write up a fix][fix].

[repo]: https://github.com/Grayson/ipspatcherFuzzer
[line]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Package.swift#L9
[hunk]: https://github.com/Grayson/ipspatcher/blob/00e840a048d1125dc385f38bca42f0e1b6b997f3/Sources/ipspatcher/Hunk.swift#L42
[fix]: https://github.com/Grayson/ipspatcher/commit/1e01fb2f788982fae7178cd0139563a60cf6d407

## So... how did we do it? (AKA Implementing the fuzzer)

Creating a fuzzer can be pretty simple.  The [example implementation][ex] doesn't do anything terribly interesting.  The [basic check][bc] is just to make sure that a `Patch` object can be created from data.  The important thing is to understand [the function signature][sig].  `@_cdecl("LLVMFuzzerTestOneInput")` is a special directive to tell the compiler what symbol name to use for the function.  Instead of `fuzz`, it'll be exposed as `LLVMFuzzerTestOneInput`.  That's the entry point for fuzzers using libFuzzer.  The parameters (`(data: UnsafePointer<CChar>, size: CInt)`) are also specified by the libFuzzer standard.  Random data comes in as `data` and the amount of data in bytes is the `size`.  You also need to return a `CInt`.  The last thing I read said that we should always return `0` and that the behavior is reserved for future libFuzzer implementations.

And that's enough to start consuming random data and passing it through some code!  We're almost done!

[ex]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Sources/ipspatcherFuzzer/main.swift#L40-L50
[bc]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Sources/ipspatcherFuzzer/main.swift#L44-L46
[sig]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Sources/ipspatcherFuzzer/main.swift#L40

## How to make better random data

Since the IPS patch format *requires* all patches to start with the phrase "PATCH", the vast majority of randomly generated data are going to be complete misses.  That's a lot of wasted cycles and won't really help you find bugs.  In order to provide better data, we can provide a custom mutator.  The custom mutator lets you introduce randomness in specific parts of your data structure.  Like the entry point, the mutator has to have a specific name (`LLVMFuzzerCustomMutator`) and uses a [specific signature][mutsig].

The [example mutator][mutator] just [replaces][replace] the input data with some custom data.  The [custom ips patch generator][custom] allocates a [randomly (but appropriately sized) memory range][alloc] and puts in the ["PATCH" and "EOF" values into a buffer][boilerplate].  It also fills in the "Hunk" segments with [randomly generated data][fuzz].

`LLVMFuzzerMutate` is the symbol that we get from FuzzerInterface, so if you don't need it, you don't need to take the dependency.  That said, the data isn't *completely* random.  It's a guided random.  The instrumentation provided by the compiler allows the fuzzer to try to create unpredictable data that exercises as many code paths as possible.

[mutator]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Sources/ipspatcherFuzzer/main.swift#L52-L59
[mutsig]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Sources/ipspatcherFuzzer/main.swift#L52
[replace]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Sources/ipspatcherFuzzer/main.swift#L55
[custom]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Sources/ipspatcherFuzzer/main.swift#L13-L37
[alloc]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Sources/ipspatcherFuzzer/main.swift#L18-L20
[boilerplate]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Sources/ipspatcherFuzzer/main.swift#L24-L34
[fuzz]: https://github.com/Grayson/ipspatcherFuzzer/blob/e4bb7439cdf47a8ab133956365c872a62dfd117f/Sources/ipspatcherFuzzer/main.swift#L22

## Concluding thoughts

libFuzzer offers a lot of additional features that we didn't dive into.  You can specify a timeout while running the fuzzer application with `-max_total_time=<seconds>`.  You can also accumulate a corpus of test cases that can be used to provide better randomized data during future test runs.  You can even specify additional data to guide the fuzzing or utilize multiple threads to test more data in less time (without writing your own threading features).

Once you've polished off the bugs that the fuzzer finds quickly, you can build the fuzzer app in the release configuration.  That'll turn on compiler optimizations and help the fuzzer test more cases in a shorter period of time.  You still get a stack trace on crashes, but it's less direct without the debugging symbols.  If you can't readily see what's wrong from the stack trace, you can then provide the crash case to a debug build to get those additional symbols.

Like all testing, fuzz testing gets the most value from being run automatically.  You may not need to fuzz test on every PR, but periodic testing with an appropriate frequency can be invaluable to finding bugs before users do.  Writing multiple fuzz testing programs, running them automatically for a reasonable amount of time, alerting on failures, and building a corpus of tests (captured from previous automated test runs) will help build confidence that the critical portions of your app are also robust.
