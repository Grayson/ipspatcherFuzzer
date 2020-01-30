import Foundation
import FuzzerInterface
import ipspatcher

private func convert<T>(data: UnsafePointer<T>, size: Int) -> String {
    return data.withMemoryRebound(to: CChar.self, capacity: size) {
        let buffer = UnsafeBufferPointer(start: $0, count: Int(size))
        let tmp = buffer.reduce(into:[], { $0.append(String(format: "0x%02x", $1)) })
        return tmp.joined(separator: " ")
    }
}

private func generateRandomPatch(maxSize: Int) -> (UnsafePointer<UInt8>, Int) {
    var rng = SystemRandomNumberGenerator()
    let patch = "PATCH".utf8CString.map { UInt8($0) }
    let eof = "EOF".utf8CString.map { UInt8($0) }

    let randomPayloadSize = Int(rng.next(upperBound: UInt(maxSize - patch.count - eof.count)))
    let totalSize = randomPayloadSize + patch.count + eof.count
    let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: totalSize)

    _ = LLVMFuzzerMutate(pointer.advanced(by: patch.count), randomPayloadSize, randomPayloadSize)

    let patchCount = patch.count
    patch.withUnsafeBytes {
        let boundMemory = $0.baseAddress!.bindMemory(to: UInt8.self, capacity: patchCount)
        pointer.assign(from: boundMemory, count: patchCount)
    }

    let eofCount = eof.count
    eof.withUnsafeBytes {
        let boundMemory = $0.baseAddress!.bindMemory(to: UInt8.self, capacity: eofCount)
        (pointer + totalSize - eofCount).assign(from: boundMemory, count: eofCount)
    }

    return (UnsafePointer<UInt8>(pointer), totalSize)
}


@_cdecl("LLVMFuzzerTestOneInput") public func fuzz(data: UnsafePointer<CChar>, size: CInt) -> CInt {
    guard size >= Patch.header.count + Patch.footer.count else { return 0 }
    let length = Int(size)
    data.withMemoryRebound(to: UInt8.self, capacity: length) { pointer in
        guard nil != Patch.from(pointer: pointer, length: length) else {
            fatalError("Unable to generate patch from:\n[\(convert(data: data, size:length))]\nsize: \(size)\n")
        }

    }
    return 0
}

@_cdecl("LLVMFuzzerCustomMutator") public func mutate(data: UnsafeMutablePointer<UInt8>, size: Int, maxSize: Int, seed: UInt32) -> Int {
    guard nil != Patch.from(pointer: data, length: size) else {
        let (patch, patchSize) = generateRandomPatch(maxSize: maxSize)
        data.initialize(from: patch, count: patchSize)
        return patchSize
    }
    return size
}
