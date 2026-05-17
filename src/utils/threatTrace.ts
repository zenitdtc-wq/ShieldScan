/**
 * ShieldScan — Threat Genesis Tracing
 *
 * Estimates threat origin using:
 * - IP geolocation from first-octet ranges (no external API, works offline)
 * - Install source detection (Play Store, sideload, ADB, etc.)
 * - Timeline construction from install/update timestamps
 */

import type { ScanResult, InstalledApp } from '../types/engine';

// ─── IP Geolocation (approximate, from first-octet ranges) ──────

interface GeoEstimate {
  region: string;
  country: string;
  confidence: 'low' | 'medium' | 'high';
  note: string;
}

const IP_REGION_MAP: Array<{
  start: number;
  end: number;
  region: string;
  country: string;
  note: string;
}> = [
  // North America
  { start: 3, end: 4, region: 'North America', country: 'US', note: 'General Electric / US allocated' },
  { start: 6, end: 7, region: 'North America', country: 'US', note: 'US DoD / Army' },
  { start: 8, end: 9, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 11, end: 11, region: 'North America', country: 'US', note: 'US DoD' },
  { start: 13, end: 15, region: 'North America', country: 'US', note: 'Xerox / HP / US allocated' },
  { start: 17, end: 19, region: 'North America', country: 'US', note: 'Apple / MIT / Ford' },
  { start: 20, end: 22, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 23, end: 23, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 34, end: 35, region: 'Europe', country: 'EU', note: 'Halliburton / RIPE allocated' },
  { start: 36, end: 38, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 40, end: 56, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 57, end: 57, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  { start: 62, end: 62, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  { start: 63, end: 76, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 77, end: 95, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  { start: 96, end: 99, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 100, end: 100, region: 'North America', country: 'US', note: 'ARIN allocated' },
  // Asia-Pacific
  { start: 101, end: 101, region: 'Asia-Pacific', country: 'APNIC', note: 'APNIC allocated' },
  { start: 103, end: 103, region: 'Asia-Pacific', country: 'APNIC', note: 'APNIC allocated' },
  { start: 106, end: 106, region: 'Asia-Pacific', country: 'CN', note: 'China allocated' },
  { start: 110, end: 112, region: 'Asia-Pacific', country: 'APNIC', note: 'APNIC allocated' },
  { start: 113, end: 126, region: 'Asia-Pacific', country: 'APNIC', note: 'APNIC allocated' },
  // Latin America
  { start: 177, end: 177, region: 'Latin America', country: 'LACNIC', note: 'LACNIC allocated' },
  { start: 179, end: 179, region: 'Latin America', country: 'LACNIC', note: 'LACNIC allocated' },
  { start: 181, end: 181, region: 'Latin America', country: 'LACNIC', note: 'LACNIC allocated' },
  { start: 186, end: 187, region: 'Latin America', country: 'BR', note: 'Brazil allocated' },
  { start: 189, end: 191, region: 'Latin America', country: 'LACNIC', note: 'LACNIC allocated' },
  // Europe continued
  { start: 141, end: 141, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  { start: 145, end: 151, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  { start: 153, end: 153, region: 'Asia-Pacific', country: 'APNIC', note: 'APNIC allocated' },
  { start: 155, end: 159, region: 'North America', country: 'US', note: 'Various / ARIN' },
  { start: 160, end: 160, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 162, end: 162, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 164, end: 168, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 169, end: 169, region: 'Private', country: '--', note: 'Link-local' },
  { start: 170, end: 170, region: 'Latin America', country: 'LACNIC', note: 'LACNIC allocated' },
  { start: 172, end: 172, region: 'Private', country: '--', note: 'Private network (172.16-31)' },
  { start: 176, end: 176, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  { start: 178, end: 178, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  { start: 185, end: 185, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  { start: 188, end: 188, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  { start: 192, end: 192, region: 'Various', country: '--', note: 'Mixed allocation / Private (192.168)' },
  { start: 193, end: 195, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  { start: 196, end: 196, region: 'Africa', country: 'AfriNIC', note: 'AfriNIC allocated' },
  { start: 197, end: 197, region: 'Africa', country: 'AfriNIC', note: 'AfriNIC allocated' },
  { start: 198, end: 199, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 200, end: 201, region: 'Latin America', country: 'LACNIC', note: 'LACNIC allocated' },
  { start: 202, end: 203, region: 'Asia-Pacific', country: 'APNIC', note: 'APNIC allocated' },
  { start: 204, end: 209, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 210, end: 211, region: 'Asia-Pacific', country: 'APNIC', note: 'APNIC allocated' },
  { start: 212, end: 213, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  { start: 216, end: 216, region: 'North America', country: 'US', note: 'ARIN allocated' },
  { start: 217, end: 217, region: 'Europe', country: 'EU', note: 'RIPE allocated' },
  // Private
  { start: 10, end: 10, region: 'Private', country: '--', note: 'RFC 1918 private network' },
  { start: 127, end: 127, region: 'Loopback', country: '--', note: 'Localhost' },
];

/**
 * Estimate geographic region from an IP address using first-octet mapping.
 * No external API needed — works fully offline.
 */
export function estimateIPGeo(ip: string): GeoEstimate {
  if (!ip || ip === '0.0.0.0' || ip === '::') {
    return { region: 'Unknown', country: '--', confidence: 'low', note: 'Invalid or empty address' };
  }

  // Handle IPv6 shorthand or full
  if (ip.includes(':')) {
    return { region: 'IPv6', country: '--', confidence: 'low', note: 'IPv6 address — first-octet mapping not applicable' };
  }

  const firstOctet = parseInt(ip.split('.')[0], 10);
  if (isNaN(firstOctet) || firstOctet < 0 || firstOctet > 255) {
    return { region: 'Unknown', country: '--', confidence: 'low', note: 'Invalid IP format' };
  }

  for (const entry of IP_REGION_MAP) {
    if (firstOctet >= entry.start && firstOctet <= entry.end) {
      const confidence = entry.region === 'Private' || entry.region === 'Loopback' ? 'high' : 'medium';
      return {
        region: entry.region,
        country: entry.country,
        confidence,
        note: entry.note,
      };
    }
  }

  return { region: 'Unknown', country: '--', confidence: 'low', note: 'Unmapped address range' };
}

// ─── Install Source Detection ───────────────────────────────────

export type InstallSource =
  | 'google_play'
  | 'samsung_store'
  | 'huawei_store'
  | 'amazon_store'
  | 'f_droid'
  | 'adb_sideload'
  | 'local_file'
  | 'package_installer'
  | 'unknown';

const INSTALLER_MAP: Record<string, InstallSource> = {
  'com.android.vending': 'google_play',
  'com.google.android.packageinstaller': 'google_play',
  'com.sec.android.app.samsungapps': 'samsung_store',
  'com.samsung.android.app.updatecenter': 'samsung_store',
  'com.huawei.appmarket': 'huawei_store',
  'com.amazon.venezia': 'amazon_store',
  'org.fdroid.fdroid': 'f_droid',
  'com.android.packageinstaller': 'package_installer',
};

const INSTALL_SOURCE_LABELS: Record<InstallSource, string> = {
  google_play: 'Google Play Store',
  samsung_store: 'Samsung Galaxy Store',
  huawei_store: 'Huawei AppGallery',
  amazon_store: 'Amazon Appstore',
  f_droid: 'F-Droid',
  adb_sideload: 'ADB / USB Sideload',
  local_file: 'Local APK File',
  package_installer: 'Package Installer (manual)',
  unknown: 'Unknown Source',
};

/**
 * Determine the install source of an app.
 * In a real native build, this would query PackageManager.getInstallerPackageName().
 * For now we estimate from app metadata.
 */
export function detectInstallSource(app: InstalledApp): {
  source: InstallSource;
  label: string;
  riskLevel: 'low' | 'medium' | 'high';
} {
  // System apps are always from the OEM
  if (app.isSystemApp) {
    return { source: 'google_play', label: 'Pre-installed (OEM)', riskLevel: 'low' };
  }

  // Check APK path patterns
  if (app.apkPath) {
    if (app.apkPath.includes('/data/app/')) {
      // User-installed, could be from any source
      // Heuristic: check package name patterns for known store packages
      if (app.packageName.startsWith('com.google.') || app.packageName.startsWith('com.android.')) {
        return { source: 'google_play', label: INSTALL_SOURCE_LABELS.google_play, riskLevel: 'low' };
      }
    }
    if (app.apkPath.includes('/system/')) {
      return { source: 'google_play', label: 'System partition', riskLevel: 'low' };
    }
  }

  // Default: mark as unknown (higher risk)
  return { source: 'unknown', label: INSTALL_SOURCE_LABELS.unknown, riskLevel: 'high' };
}

// ─── Threat Timeline ────────────────────────────────────────────

export interface ThreatTimelineEvent {
  timestamp: number;
  type: 'installed' | 'updated' | 'first_detected' | 'connection' | 'permission_granted';
  label: string;
  detail: string;
  severity: 'info' | 'warning' | 'danger';
}

/**
 * Build a timeline of events for a specific threat/app finding.
 */
export function buildThreatTimeline(
  result: ScanResult,
  app?: InstalledApp,
): ThreatTimelineEvent[] {
  const events: ThreatTimelineEvent[] = [];

  if (app) {
    // App install event
    events.push({
      timestamp: app.installTime,
      type: 'installed',
      label: 'App Installed',
      detail: `${app.appName} (${app.packageName}) was installed`,
      severity: 'info',
    });

    // App update event (if different from install)
    if (app.lastUpdateTime && app.lastUpdateTime !== app.installTime) {
      events.push({
        timestamp: app.lastUpdateTime,
        type: 'updated',
        label: 'App Updated',
        detail: `Updated to version ${app.versionName || 'unknown'}`,
        severity: 'info',
      });
    }

    // Permission grants (we know they're granted but not when)
    const dangerousPerms = app.permissions.filter(
      (p) => p.granted && (p.riskLevel === 'high' || p.riskLevel === 'critical')
    );
    if (dangerousPerms.length > 0) {
      events.push({
        timestamp: app.installTime + 1000, // Assume right after install
        type: 'permission_granted',
        label: 'Dangerous Permissions Granted',
        detail: `${dangerousPerms.length} high-risk permissions: ${dangerousPerms.slice(0, 3).map((p) => p.name.split('.').pop()).join(', ')}`,
        severity: 'warning',
      });
    }
  }

  // Detection event
  events.push({
    timestamp: result.timestamp,
    type: 'first_detected',
    label: 'Threat Detected',
    detail: result.title,
    severity: 'danger',
  });

  // Sort chronologically
  events.sort((a, b) => a.timestamp - b.timestamp);

  return events;
}

// ─── Full Threat Origin Report ──────────────────────────────────

export interface ThreatOriginReport {
  finding: ScanResult;
  installSource: { source: InstallSource; label: string; riskLevel: string } | null;
  networkGeo: GeoEstimate | null;
  timeline: ThreatTimelineEvent[];
  riskFactors: string[];
}

/**
 * Generate a complete threat origin report for a finding.
 */
export function generateThreatOrigin(
  result: ScanResult,
  apps: InstalledApp[],
): ThreatOriginReport {
  const app = result.packageName
    ? apps.find((a) => a.packageName === result.packageName)
    : undefined;

  const installSource = app ? detectInstallSource(app) : null;

  // Extract remote IP from evidence if network finding
  let networkGeo: GeoEstimate | null = null;
  if (result.moduleId === 'network' && result.evidence) {
    const remoteEvidence = result.evidence.find((e) => e.startsWith('Remote:'));
    if (remoteEvidence) {
      const ip = remoteEvidence.replace('Remote:', '').trim().split(':')[0];
      networkGeo = estimateIPGeo(ip);
    }
  }

  const timeline = buildThreatTimeline(result, app);

  // Build risk factor list
  const riskFactors: string[] = [];
  if (result.severity === 'critical') riskFactors.push('Critical severity threat');
  if (result.severity === 'high') riskFactors.push('High severity threat');
  if (installSource?.riskLevel === 'high') riskFactors.push('Installed from unknown source');
  if (app && !app.isSystemApp) riskFactors.push('Third-party application');
  if (networkGeo?.region === 'Unknown') riskFactors.push('Connection to unmapped IP range');
  if (result.moduleId === 'network') riskFactors.push('Active network communication detected');
  if (result.moduleId === 'signature') riskFactors.push('Matches known malware signature');

  return {
    finding: result,
    installSource,
    networkGeo,
    timeline,
    riskFactors,
  };
}
