import Foundation

public enum OverflowPolicy: String, Sendable {
  case dropNewest
  case dropOldest
}

public struct BoundedEventBuffer<Element: Sendable>: Sendable {
  public let capacity: Int
  public let overflowPolicy: OverflowPolicy

  private var storage: [Element] = []
  public private(set) var droppedCount = 0
  public private(set) var highWatermark = 0

  public init(capacity: Int, overflowPolicy: OverflowPolicy = .dropNewest) throws {
    guard capacity > 0 else {
      throw SensorError.invalidArgument("queue capacity must be greater than zero")
    }
    self.capacity = capacity
    self.overflowPolicy = overflowPolicy
    storage.reserveCapacity(capacity)
  }

  public var count: Int { storage.count }
  public var isEmpty: Bool { storage.isEmpty }

  @discardableResult
  public mutating func append(_ element: Element) -> Bool {
    if storage.count == capacity {
      droppedCount += 1
      switch overflowPolicy {
      case .dropNewest:
        return false
      case .dropOldest:
        storage.removeFirst()
      }
    }
    storage.append(element)
    highWatermark = max(highWatermark, storage.count)
    return true
  }

  public mutating func drain(maxCount: Int? = nil) -> [Element] {
    let requested = maxCount.map { max(0, $0) } ?? storage.count
    let count = min(requested, storage.count)
    guard count > 0 else { return [] }
    let drained = Array(storage.prefix(count))
    storage.removeFirst(count)
    return drained
  }
}
