import CryptoKit
import Foundation

public struct PrivacyFilter: Sendable {
  private let salt: String

  public init(salt: String) throws {
    guard salt.utf8.count >= 16 else {
      throw SensorError.invalidArgument("privacy salt must contain at least 16 UTF-8 bytes")
    }
    self.salt = salt
  }

  public func normalize(_ event: RawMacOSEvent) -> NormalizedMacOSEvent {
    NormalizedMacOSEvent(
      eventID: token(prefix: "event", value: event.eventID),
      timestamp: event.timestamp,
      hostToken: token(prefix: "host", value: event.hostID),
      userToken: token(prefix: "user", value: event.userID),
      sessionToken: token(prefix: "session", value: event.sessionID),
      step: event.step,
      parentProcess: sanitizeProcess(event.parentProcess),
      process: sanitizeProcess(event.process),
      eventType: event.eventType,
      targetKind: targetKind(event.target),
      targetToken: token(prefix: "target", value: event.target),
      relation: event.relation,
      signed: event.signed,
      notarized: event.notarized,
      gatekeeperBypass: event.gatekeeperBypass,
      xprotectDetection: event.xprotectDetection,
      privilegeEscalation: event.privilegeEscalation,
      persistenceWrite: event.persistenceWrite,
      sensitiveAccess: event.sensitiveAccess,
      networkBeacon: event.networkBeacon,
      fileWriteCount: max(0, event.fileWriteCount),
      bytesOut: max(0, event.bytesOut),
      commandRisk: min(max(event.commandRisk, 0), 1),
      scenario: event.scenario,
      mitreTechnique: event.mitreTechnique,
      label: event.label == 0 ? 0 : 1,
      dataSource: event.dataSource
    )
  }

  private func token(prefix: String, value: String) -> String {
    let digest = SHA256.hash(data: Data("\(salt):\(value)".utf8))
    let compact = digest.prefix(10).map { String(format: "%02x", $0) }.joined()
    return "\(prefix)-\(compact)"
  }

  private func sanitizeProcess(_ value: String) -> String {
    let basename = URL(fileURLWithPath: value).lastPathComponent
    let allowed = basename.unicodeScalars.filter {
      CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-+")).contains($0)
    }
    return String(String.UnicodeScalarView(allowed)).prefix(96).description
  }

  private func targetKind(_ target: String) -> String {
    if target.hasPrefix("/") || target.contains("\\") { return "path" }
    if target.contains(".") { return "network-or-file" }
    return "resource"
  }
}
