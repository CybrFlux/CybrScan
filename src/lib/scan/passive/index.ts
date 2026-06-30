// CybrScan — passive check library public surface (CYB-43).
// Implements §2 Tier-P checks, §8 rubric + severity table, §7.2 output shape.

export * from './types'
export { CATALOG, ALL_FINDING_IDS, catalogEntry, type CatalogEntry, type FindingId } from './catalog'
export {
  checkTls,
  checkHeaders,
  checkCookies,
  checkDnsEmail,
  runChecks,
} from './checks'
export { categoryGrade, categoryScore, gradeScan, type Grading } from './grading'
export {
  formatReport,
  formatReportMarkdown,
  sortFindings,
  assertReportSafe,
  type SafeReport,
  type ReportLine,
} from './formatter'
export {
  isSafeOutput,
  scanForPayloads,
  assertSafeOutput,
  UnsafeReportError,
} from './safe-output'
export {
  runPassiveScan,
  createPassiveEngine,
  PASSIVE_ENGINE_VERSION,
  type ObservationFetcher,
} from './engine'
