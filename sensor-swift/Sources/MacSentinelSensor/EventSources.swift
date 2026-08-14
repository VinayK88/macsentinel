import Foundation

public protocol MacOSEventSource {
  var sourceName: String { get }
  func forEachEvent(_ consume: (RawMacOSEvent) throws -> Void) throws
}

public struct ReplayCSVEventSource: MacOSEventSource, Sendable {
  public let inputURL: URL
  public var sourceName: String { "csv-replay:\(inputURL.lastPathComponent)" }

  public init(inputURL: URL) {
    self.inputURL = inputURL
  }

  public func forEachEvent(_ consume: (RawMacOSEvent) throws -> Void) throws {
    let content = try String(contentsOf: inputURL, encoding: .utf8)
    let lines = content.split(whereSeparator: \Character.isNewline).map(String.init)
    guard let headerLine = lines.first else {
      throw SensorError.invalidCSV("file is empty")
    }
    let header = parseCSVLine(headerLine)
    let required = RawMacOSEvent.requiredColumns
    let missing = required.filter { !header.contains($0) }
    guard missing.isEmpty else {
      throw SensorError.invalidCSV("missing columns: \(missing.joined(separator: ", "))")
    }

    for (offset, line) in lines.dropFirst().enumerated() where !line.isEmpty {
      let values = parseCSVLine(line)
      guard values.count == header.count else {
        throw SensorError.invalidCSV(
          "line \(offset + 2) has \(values.count) values; expected \(header.count)")
      }
      let row = Dictionary(uniqueKeysWithValues: zip(header, values))
      try consume(try RawMacOSEvent(csvRow: row, lineNumber: offset + 2))
    }
  }
}

/// Public boundary for an authorized Endpoint Security client.
///
/// The open-source package intentionally does not create an `es_client_t`. A deployment
/// with Apple's restricted entitlement can translate metadata into this value and feed it
/// through the same privacy filter, bounded buffer, and benchmarked pipeline as replay data.
public struct AuthorizedEndpointSecurityMetadata: Equatable, Sendable {
  public let event: RawMacOSEvent

  public init(event: RawMacOSEvent) {
    self.event = event
  }
}

public struct EndpointSecurityMetadataSource: MacOSEventSource, Sendable {
  public let metadata: [AuthorizedEndpointSecurityMetadata]
  public var sourceName: String { "authorized-endpoint-security-metadata" }

  public init(metadata: [AuthorizedEndpointSecurityMetadata]) {
    self.metadata = metadata
  }

  public func forEachEvent(_ consume: (RawMacOSEvent) throws -> Void) throws {
    for item in metadata {
      try consume(item.event)
    }
  }
}

public enum LiveEndpointSecuritySource {
  public static func requireAuthorization() throws -> Never {
    throw SensorError.endpointSecurityEntitlementRequired
  }
}

public func parseCSVLine(_ line: String) -> [String] {
  var values: [String] = []
  var current = ""
  var quoted = false
  var index = line.startIndex

  while index < line.endIndex {
    let character = line[index]
    if character == "\"" {
      let next = line.index(after: index)
      if quoted, next < line.endIndex, line[next] == "\"" {
        current.append("\"")
        index = next
      } else {
        quoted.toggle()
      }
    } else if character == "," && !quoted {
      values.append(current)
      current = ""
    } else {
      current.append(character)
    }
    index = line.index(after: index)
  }
  values.append(current)
  return values
}

extension RawMacOSEvent {
  fileprivate static let requiredColumns = [
    "event_id", "timestamp", "host_id", "user_hash", "session_id", "step",
    "parent_process", "process", "event_type", "target", "relation", "signed",
    "notarized", "gatekeeper_bypass", "xprotect_detection", "privilege_escalation",
    "persistence_write", "sensitive_access", "network_beacon", "file_write_count",
    "bytes_out", "command_risk", "scenario", "mitre_technique", "label", "data_source",
  ]

  fileprivate init(csvRow row: [String: String], lineNumber: Int) throws {
    func value(_ key: String) throws -> String {
      guard let value = row[key] else {
        throw SensorError.invalidCSV("line \(lineNumber) has no value for \(key)")
      }
      return value
    }
    func integer(_ key: String) throws -> Int {
      let raw = try value(key)
      guard let result = Int(raw) else {
        throw SensorError.invalidCSV("line \(lineNumber) has invalid integer for \(key): \(raw)")
      }
      return result
    }
    func double(_ key: String) throws -> Double {
      let raw = try value(key)
      guard let result = Double(raw) else {
        throw SensorError.invalidCSV("line \(lineNumber) has invalid number for \(key): \(raw)")
      }
      return result
    }
    func boolean(_ key: String) throws -> Bool {
      let raw = try integer(key)
      guard raw == 0 || raw == 1 else {
        throw SensorError.invalidCSV("line \(lineNumber) has invalid boolean for \(key): \(raw)")
      }
      return raw == 1
    }

    self.init(
      eventID: try value("event_id"),
      timestamp: try value("timestamp"),
      hostID: try value("host_id"),
      userID: try value("user_hash"),
      sessionID: try value("session_id"),
      step: try integer("step"),
      parentProcess: try value("parent_process"),
      process: try value("process"),
      eventType: try value("event_type"),
      target: try value("target"),
      relation: try value("relation"),
      signed: try boolean("signed"),
      notarized: try boolean("notarized"),
      gatekeeperBypass: try boolean("gatekeeper_bypass"),
      xprotectDetection: try boolean("xprotect_detection"),
      privilegeEscalation: try boolean("privilege_escalation"),
      persistenceWrite: try boolean("persistence_write"),
      sensitiveAccess: try boolean("sensitive_access"),
      networkBeacon: try boolean("network_beacon"),
      fileWriteCount: try integer("file_write_count"),
      bytesOut: try integer("bytes_out"),
      commandRisk: try double("command_risk"),
      scenario: try value("scenario"),
      mitreTechnique: try value("mitre_technique"),
      label: try integer("label"),
      dataSource: try value("data_source")
    )
  }
}
