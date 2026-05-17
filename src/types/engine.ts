/**
 * ShieldScan Engine — Core Type Definitions
 * Extended for real native Android scanning
 */

// ─── Severity & Status ───────────────────────────────────────
export type SeverityLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export type ScanModuleStatus = 'queued' | 'scanning' | 'complete' | 'error';
export type ScanSessionStatus = 'idle' | 'running' | 'complete' | 'aborted';

// ─── Scan Module ─────────────────────────────────────────────
export interface ScanModule {
  id: string;
  name: string;
  description: string;
  icon: string;
  accentColor: string;
  status: ScanModuleStatus;
  findingsCount: number;
  duration?: number;
  progress?: number; // 0-100 per module
}

// ─── Scan Result (Finding) ───────────────────────────────────
export interface ScanResult {
  id: string;
  moduleId: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  recommendation: string;
  timestamp: number;
  evidence?: string[];
  packageName?: string;   // Android package involved
  filePath?: string;      // File path if applicable
  hash?: string;          // File hash if applicable
  confidence?: number;    // 0-100 agent confidence score
  agentId?: string;       // Which agent produced this finding
  correlated?: boolean;   // Whether this is a cross-agent correlated finding
  correlatedAgents?: string[]; // Agent IDs that agree on this finding
}

// ─── Risk Score ──────────────────────────────────────────────
export interface RiskScore {
  overall: number; // 0-100
  breakdown: Record<string, number>;
  level: SeverityLevel;
  summary: string;
}

// ─── Scan Session ────────────────────────────────────────────
export interface ScanSession {
  id: string;
  startedAt: number;
  completedAt?: number;
  modules: ScanModule[];
  results: ScanResult[];
  riskScore: RiskScore;
  status: ScanSessionStatus;
}

// ─── Installed App Info (from native) ────────────────────────
export interface InstalledApp {
  packageName: string;
  appName: string;
  versionName: string;
  versionCode: number;
  isSystemApp: boolean;
  installTime: number;
  lastUpdateTime: number;
  permissions: AppPermission[];
  apkPath: string;
  apkSize: number;
  sha256?: string;
}

export interface AppPermission {
  name: string;
  granted: boolean;
  riskLevel: SeverityLevel;
  description: string;
  group?: string;
}

// ─── Running Service (from native) ───────────────────────────
export interface RunningServiceInfo {
  packageName: string;
  serviceName: string;
  pid: number;
  isForeground: boolean;
  memoryUsageKb: number;
  startTime?: number;
}

// ─── Network Connection (from native) ────────────────────────
export interface NetworkConnection {
  protocol: 'TCP' | 'UDP';
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
  packageName?: string;
  uid?: number;
}

// ─── System Integrity Info (from native) ─────────────────────
export interface SystemIntegrityInfo {
  isRooted: boolean;
  isBootloaderUnlocked: boolean;
  isDeveloperModeEnabled: boolean;
  isUsbDebuggingEnabled: boolean;
  isAdbOverWifi: boolean;
  isEncrypted: boolean;
  securityPatchDate: string;
  androidVersion: string;
  buildFingerprint: string;
  seLinuxStatus: 'enforcing' | 'permissive' | 'disabled' | 'unknown';
}

// ─── Threat Family (Intel DB) ────────────────────────────────
export interface ThreatFamily {
  id: string;
  name: string;
  aliases: string[];
  severity: SeverityLevel;
  category: string;
  description: string;
  indicators: string[];
  detectionCount: number;
  firstSeen: string;
  lastSeen: string;
  yaraRule?: string;        // YARA rule pattern
  packagePatterns?: string[]; // Regex patterns for package names
  hashSignatures?: string[]; // Known malicious file hashes
  c2Domains?: string[];     // C2 server domains
}

// ─── Remediation ─────────────────────────────────────────────
export interface RemediationWorkflow {
  id: string;
  threatId: string;
  threatName: string;
  severity: SeverityLevel;
  category: string;
  description: string;
  steps: RemediationStep[];
  estimatedMinutes: number;
}

export interface RemediationStep {
  id: string;
  order: number;
  title: string;
  description: string;
  action: 'uninstall' | 'revoke_permission' | 'disable_service' | 'block_network' | 'manual' | 'verify';
  targetPackage?: string;
  targetPermission?: string;
  requiresManualAction: boolean;
  completed: boolean;
}

// ─── Verification ────────────────────────────────────────────
export interface VerificationItem {
  id: string;
  label: string;
  description: string;
  checked: boolean;
  autoVerifiable: boolean;
  passed?: boolean;
}

// ─── Action Log ──────────────────────────────────────────────
export interface ActionLogEntry {
  id: string;
  timestamp: number;
  action: string;
  target: string;
  status: 'success' | 'failed' | 'skipped' | 'pending';
  details?: string;
}
