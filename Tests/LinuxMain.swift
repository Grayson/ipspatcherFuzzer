import XCTest

import ipspatcherFuzzerTests

var tests = [XCTestCaseEntry]()
tests += ipspatcherFuzzerTests.allTests()
XCTMain(tests)
