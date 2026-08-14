import Darwin
import Foundation

public struct SensorPipeline {
  public let privacyFilter: PrivacyFilter
  public let queueCapacity: Int
  public let batchSize: Int
  public let overflowPolicy: OverflowPolicy

  public init(
    privacyFilter: PrivacyFilter,
    queueCapacity: Int = 256,
    batchSize: Int = 64,
    overflowPolicy: OverflowPolicy = .dropNewest
  ) throws {
    guard batchSize > 0 else {
      throw SensorError.invalidArgument("batch size must be greater than zero")
    }
    guard batchSize <= queueCapacity else {
      throw SensorError.invalidArgument("batch size cannot exceed queue capacity")
    }
    self.privacyFilter = privacyFilter
    self.queueCapacity = queueCapacity
    self.batchSize = batchSize
    self.overflowPolicy = overflowPolicy
  }

  public func run<Source: MacOSEventSource>(
    source: Source,
    sink: ([NormalizedMacOSEvent]) throws -> Void = { _ in }
  ) throws -> BenchmarkReport {
    var queue = try BoundedEventBuffer<NormalizedMacOSEvent>(
      capacity: queueCapacity,
      overflowPolicy: overflowPolicy
    )
    var eventsRead = 0
    var eventsEmitted = 0
    var normalizationNanos: [UInt64] = []
    var rawIdentifiersObserved = 0
    var rawTargetsObserved = 0
    normalizationNanos.reserveCapacity(4_096)

    let start = DispatchTime.now().uptimeNanoseconds
    try source.forEachEvent { rawEvent in
      eventsRead += 1
      let eventStart = DispatchTime.now().uptimeNanoseconds
      let normalized = privacyFilter.normalize(rawEvent)
      normalizationNanos.append(DispatchTime.now().uptimeNanoseconds - eventStart)

      let encoded = try JSONEncoder().encode(normalized)
      let rendered = String(decoding: encoded, as: UTF8.self)
      let rawIdentifiers = [
        rawEvent.eventID, rawEvent.hostID, rawEvent.userID, rawEvent.sessionID,
      ].filter { !$0.isEmpty }
      if rawIdentifiers.contains(where: rendered.contains) {
        rawIdentifiersObserved += 1
      }
      if !rawEvent.target.isEmpty && rendered.contains(rawEvent.target) {
        rawTargetsObserved += 1
      }

      _ = queue.append(normalized)
      if queue.count >= batchSize {
        let batch = queue.drain(maxCount: batchSize)
        try sink(batch)
        eventsEmitted += batch.count
      }
    }

    let finalBatch = queue.drain()
    if !finalBatch.isEmpty {
      try sink(finalBatch)
      eventsEmitted += finalBatch.count
    }
    let elapsedNanos = DispatchTime.now().uptimeNanoseconds - start
    let elapsedSeconds = max(Double(elapsedNanos) / 1_000_000_000, 0.000_001)

    return BenchmarkReport(
      source: source.sourceName,
      eventsRead: eventsRead,
      eventsEmitted: eventsEmitted,
      eventsDropped: queue.droppedCount,
      queueCapacity: queue.capacity,
      queueHighWatermark: queue.highWatermark,
      elapsedMilliseconds: elapsedSeconds * 1_000,
      eventsPerSecond: Double(eventsRead) / elapsedSeconds,
      p50NormalizationMicros: percentile(normalizationNanos, 0.50) / 1_000,
      p95NormalizationMicros: percentile(normalizationNanos, 0.95) / 1_000,
      peakResidentMemoryMB: peakResidentMemoryMB(),
      rawIdentifiersObservedInOutput: rawIdentifiersObserved,
      rawTargetsObservedInOutput: rawTargetsObserved,
      privacyChecksPassed: rawIdentifiersObserved == 0 && rawTargetsObserved == 0
    )
  }
}

private func percentile(_ values: [UInt64], _ fraction: Double) -> Double {
  guard !values.isEmpty else { return 0 }
  let sorted = values.sorted()
  let index = Int((Double(sorted.count - 1) * fraction).rounded())
  return Double(sorted[min(max(index, 0), sorted.count - 1)])
}

private func peakResidentMemoryMB() -> Double {
  var usage = rusage()
  guard getrusage(RUSAGE_SELF, &usage) == 0 else { return 0 }
  return Double(usage.ru_maxrss) / 1_048_576
}
