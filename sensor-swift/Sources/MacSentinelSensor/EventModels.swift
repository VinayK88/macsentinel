import Foundation

public enum SensorError: Error, CustomStringConvertible, Equatable {
  case invalidCSV(String)
  case invalidArgument(String)
  case endpointSecurityEntitlementRequired

  public var description: String {
    switch self {
    case .invalidCSV(let message):
      return "Invalid CSV: \(message)"
    case .invalidArgument(let message):
      return "Invalid argument: \(message)"
    case .endpointSecurityEntitlementRequired:
      return
        "Live Endpoint Security collection requires Apple authorization, the Endpoint Security entitlement, and an approved deployment context."
    }
  }
}

public struct RawMacOSEvent: Equatable, Sendable {
  public let eventID: String
  public let timestamp: String
  public let hostID: String
  public let userID: String
  public let sessionID: String
  public let step: Int
  public let parentProcess: String
  public let process: String
  public let eventType: String
  public let target: String
  public let relation: String
  public let signed: Bool
  public let notarized: Bool
  public let gatekeeperBypass: Bool
  public let xprotectDetection: Bool
  public let privilegeEscalation: Bool
  public let persistenceWrite: Bool
  public let sensitiveAccess: Bool
  public let networkBeacon: Bool
  public let fileWriteCount: Int
  public let bytesOut: Int
  public let commandRisk: Double
  public let scenario: String
  public let mitreTechnique: String
  public let label: Int
  public let dataSource: String

  public init(
    eventID: String,
    timestamp: String,
    hostID: String,
    userID: String,
    sessionID: String,
    step: Int,
    parentProcess: String,
    process: String,
    eventType: String,
    target: String,
    relation: String,
    signed: Bool,
    notarized: Bool,
    gatekeeperBypass: Bool,
    xprotectDetection: Bool,
    privilegeEscalation: Bool,
    persistenceWrite: Bool,
    sensitiveAccess: Bool,
    networkBeacon: Bool,
    fileWriteCount: Int,
    bytesOut: Int,
    commandRisk: Double,
    scenario: String,
    mitreTechnique: String,
    label: Int,
    dataSource: String
  ) {
    self.eventID = eventID
    self.timestamp = timestamp
    self.hostID = hostID
    self.userID = userID
    self.sessionID = sessionID
    self.step = step
    self.parentProcess = parentProcess
    self.process = process
    self.eventType = eventType
    self.target = target
    self.relation = relation
    self.signed = signed
    self.notarized = notarized
    self.gatekeeperBypass = gatekeeperBypass
    self.xprotectDetection = xprotectDetection
    self.privilegeEscalation = privilegeEscalation
    self.persistenceWrite = persistenceWrite
    self.sensitiveAccess = sensitiveAccess
    self.networkBeacon = networkBeacon
    self.fileWriteCount = fileWriteCount
    self.bytesOut = bytesOut
    self.commandRisk = commandRisk
    self.scenario = scenario
    self.mitreTechnique = mitreTechnique
    self.label = label
    self.dataSource = dataSource
  }
}

public struct NormalizedMacOSEvent: Codable, Equatable, Sendable {
  public let eventID: String
  public let timestamp: String
  public let hostToken: String
  public let userToken: String
  public let sessionToken: String
  public let step: Int
  public let parentProcess: String
  public let process: String
  public let eventType: String
  public let targetKind: String
  public let targetToken: String
  public let relation: String
  public let signed: Bool
  public let notarized: Bool
  public let gatekeeperBypass: Bool
  public let xprotectDetection: Bool
  public let privilegeEscalation: Bool
  public let persistenceWrite: Bool
  public let sensitiveAccess: Bool
  public let networkBeacon: Bool
  public let fileWriteCount: Int
  public let bytesOut: Int
  public let commandRisk: Double
  public let scenario: String
  public let mitreTechnique: String
  public let label: Int
  public let dataSource: String
}

public struct BenchmarkReport: Codable, Equatable, Sendable {
  public let source: String
  public let eventsRead: Int
  public let eventsEmitted: Int
  public let eventsDropped: Int
  public let queueCapacity: Int
  public let queueHighWatermark: Int
  public let elapsedMilliseconds: Double
  public let eventsPerSecond: Double
  public let p50NormalizationMicros: Double
  public let p95NormalizationMicros: Double
  public let peakResidentMemoryMB: Double
  public let rawIdentifiersObservedInOutput: Int
  public let rawTargetsObservedInOutput: Int
  public let privacyChecksPassed: Bool
}
