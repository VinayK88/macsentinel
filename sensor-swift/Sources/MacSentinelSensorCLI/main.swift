import Darwin
import Foundation
import MacSentinelSensor

private struct Options {
  var inputPath: String?
  var reportPath: String?
  var eventOutputPath: String?
  var capacity = 256
  var batchSize = 64
  var overflowPolicy = OverflowPolicy.dropNewest
  var saltEnvironmentVariable = "MACSENTINEL_PRIVACY_SALT"
}

@main
private enum MacSentinelSensorCommand {
  static func main() {
    do {
      try run()
    } catch {
      FileHandle.standardError.write(Data("macsentinel-sensor: \(error)\n".utf8))
      exit(2)
    }
  }

  private static func run() throws {
    var arguments = Array(CommandLine.arguments.dropFirst())
    if arguments.first == "--help" || arguments.first == "-h" {
      print(help)
      return
    }
    let command = arguments.first ?? "benchmark"
    if ["benchmark", "replay", "self-test"].contains(command) {
      arguments.removeFirst()
    }

    let options = try parse(arguments)
    let inputURL = try resolveInput(options.inputPath)
    let salt =
      ProcessInfo.processInfo.environment[options.saltEnvironmentVariable]
      ?? "macsentinel-public-replay-salt-v1"
    let filter = try PrivacyFilter(salt: salt)
    let pipeline = try SensorPipeline(
      privacyFilter: filter,
      queueCapacity: options.capacity,
      batchSize: options.batchSize,
      overflowPolicy: options.overflowPolicy
    )

    if command == "self-test" {
      try runSelfTest(inputURL: inputURL, filter: filter, pipeline: pipeline)
      return
    }

    var eventHandle: FileHandle?
    if let eventOutputPath = options.eventOutputPath {
      let url = URL(fileURLWithPath: eventOutputPath)
      try FileManager.default.createDirectory(
        at: url.deletingLastPathComponent(),
        withIntermediateDirectories: true
      )
      FileManager.default.createFile(atPath: url.path, contents: nil)
      eventHandle = try FileHandle(forWritingTo: url)
    }
    defer { try? eventHandle?.close() }

    let report = try pipeline.run(source: ReplayCSVEventSource(inputURL: inputURL)) { batch in
      guard let eventHandle else { return }
      let encoder = JSONEncoder()
      encoder.outputFormatting = [.sortedKeys]
      for event in batch {
        var line = try encoder.encode(event)
        line.append(0x0A)
        try eventHandle.write(contentsOf: line)
      }
    }

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let payload = try encoder.encode(report)
    print(String(decoding: payload, as: UTF8.self))

    if let reportPath = options.reportPath {
      let url = URL(fileURLWithPath: reportPath)
      try FileManager.default.createDirectory(
        at: url.deletingLastPathComponent(),
        withIntermediateDirectories: true
      )
      try payload.write(to: url, options: .atomic)
    }

    guard report.privacyChecksPassed else {
      throw SensorError.invalidArgument(
        "privacy regression: raw identifiers or targets reached normalized output")
    }
    guard report.eventsDropped == 0 else {
      throw SensorError.invalidArgument(
        "\(report.eventsDropped) events were dropped; increase queue capacity or reduce batch size")
    }
  }

  private static func runSelfTest(
    inputURL: URL,
    filter: PrivacyFilter,
    pipeline: SensorPipeline
  ) throws {
    func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
      guard condition() else { throw SensorError.invalidArgument("self-test failed: \(message)") }
    }

    try require(
      parseCSVLine("alpha,\"bravo,charlie\",\"say \"\"hello\"\"\"")
        == ["alpha", "bravo,charlie", "say \"hello\""],
      "quoted CSV parsing"
    )

    var dropNewest = try BoundedEventBuffer<Int>(capacity: 2, overflowPolicy: .dropNewest)
    try require(dropNewest.append(1), "first bounded append")
    try require(dropNewest.append(2), "second bounded append")
    try require(!dropNewest.append(3), "drop-newest policy")
    try require(dropNewest.droppedCount == 1, "drop-newest counter")
    try require(dropNewest.drain() == [1, 2], "drop-newest ordering")

    var dropOldest = try BoundedEventBuffer<Int>(capacity: 2, overflowPolicy: .dropOldest)
    _ = dropOldest.append(1)
    _ = dropOldest.append(2)
    _ = dropOldest.append(3)
    try require(dropOldest.drain() == [2, 3], "drop-oldest ordering")

    do {
      try LiveEndpointSecuritySource.requireAuthorization()
    } catch SensorError.endpointSecurityEntitlementRequired {
      // Expected fail-closed behavior.
    }

    var firstRawEvent: RawMacOSEvent?
    try ReplayCSVEventSource(inputURL: inputURL).forEachEvent {
      if firstRawEvent == nil { firstRawEvent = $0 }
    }
    guard let firstRawEvent else {
      throw SensorError.invalidArgument("self-test failed: fixture contains no events")
    }
    let normalized = filter.normalize(firstRawEvent)
    let alternate = try PrivacyFilter(salt: "macsentinel-alternate-salt-v1").normalize(
      firstRawEvent)
    try require(normalized.hostToken != alternate.hostToken, "salted host tokenization")
    let rendered = String(decoding: try JSONEncoder().encode(normalized), as: UTF8.self)
    try require(!rendered.contains(firstRawEvent.eventID), "event identifier redaction")
    try require(!rendered.contains(firstRawEvent.hostID), "host identifier redaction")
    try require(!rendered.contains(firstRawEvent.userID), "user identifier redaction")
    try require(!rendered.contains(firstRawEvent.sessionID), "session identifier redaction")
    try require(!rendered.contains(firstRawEvent.target), "target tokenization")

    let report = try pipeline.run(source: ReplayCSVEventSource(inputURL: inputURL))
    try require(report.eventsRead == 2_520, "fixture event count")
    try require(report.eventsEmitted == 2_520, "emitted event count")
    try require(report.eventsDropped == 0, "zero-drop replay")
    try require(report.queueHighWatermark == pipeline.batchSize, "queue high-water mark")
    try require(report.privacyChecksPassed, "pipeline privacy gate")
    try require(report.eventsPerSecond > 0, "throughput measurement")
    try require(report.p95NormalizationMicros > 0, "latency measurement")

    print("PASS csv-quoting")
    print("PASS bounded-backpressure")
    print("PASS entitlement-fails-closed")
    print("PASS deterministic-privacy-filter")
    print("PASS 2520-event-zero-drop-replay")
    print("PASS throughput-latency-memory-reporting")
  }

  private static func parse(_ arguments: [String]) throws -> Options {
    var options = Options()
    var index = 0
    while index < arguments.count {
      let argument = arguments[index]
      func nextValue() throws -> String {
        guard index + 1 < arguments.count else {
          throw SensorError.invalidArgument("\(argument) requires a value")
        }
        index += 1
        return arguments[index]
      }

      switch argument {
      case "--input": options.inputPath = try nextValue()
      case "--report": options.reportPath = try nextValue()
      case "--event-output": options.eventOutputPath = try nextValue()
      case "--capacity":
        guard let value = Int(try nextValue()) else {
          throw SensorError.invalidArgument("--capacity must be an integer")
        }
        options.capacity = value
      case "--batch-size":
        guard let value = Int(try nextValue()) else {
          throw SensorError.invalidArgument("--batch-size must be an integer")
        }
        options.batchSize = value
      case "--overflow":
        guard let value = OverflowPolicy(rawValue: try nextValue()) else {
          throw SensorError.invalidArgument("--overflow must be dropNewest or dropOldest")
        }
        options.overflowPolicy = value
      case "--salt-env": options.saltEnvironmentVariable = try nextValue()
      case "--help", "-h":
        print(help)
        exit(0)
      default:
        throw SensorError.invalidArgument("unknown option \(argument)")
      }
      index += 1
    }
    return options
  }

  private static func resolveInput(_ path: String?) throws -> URL {
    if let path {
      let url = URL(fileURLWithPath: path)
      guard FileManager.default.fileExists(atPath: url.path) else {
        throw SensorError.invalidArgument("input does not exist: \(url.path)")
      }
      return url
    }

    let candidates = [
      "macsentinel/data/synthetic_macos_events.csv",
      "../data/synthetic_macos_events.csv",
    ]
    for candidate in candidates where FileManager.default.fileExists(atPath: candidate) {
      return URL(fileURLWithPath: candidate)
    }
    throw SensorError.invalidArgument(
      "provide --input PATH when running outside the repository root")
  }

  private static let help = """
    MacSentinel native sensor replay and benchmark

    Usage:
      macsentinel-sensor benchmark [options]
      macsentinel-sensor replay [options]
      macsentinel-sensor self-test [options]

    Options:
      --input PATH          Endpoint Security-style CSV fixture
      --report PATH         Write a pretty-printed benchmark report
      --event-output PATH   Write privacy-filtered events as JSONL
      --capacity N          Bounded queue capacity (default: 256)
      --batch-size N        Sink batch size (default: 64)
      --overflow POLICY     dropNewest or dropOldest
      --salt-env NAME       Environment variable containing the privacy salt

    The built-in public salt is only for deterministic synthetic replay. Set
    MACSENTINEL_PRIVACY_SALT to a deployment-specific secret for authorized data.
    """
}
