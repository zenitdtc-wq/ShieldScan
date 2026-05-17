/**
 * ShieldScan Engine Hook
 *
 * Orchestrates the 5-module scanning pipeline.
 * Calls native Android APIs through NativeBridge, analyzes results,
 * and produces risk scores + actionable findings.
 */

import { useState, useCallback, useRef } from 'react';
import type {
  ScanModule,
  ScanResult,
  RiskScore,
  ScanSessionStatus,
  SeverityLevel,
  InstalledApp,
} from '../types/engine';
import { defaultModules } from '../data/modules';
import { threatFamilies, dangerousPermCombos, knownC2Domains } from '../data/threats';
import {
  maliciousPackagePatterns,
  expandedDangerousPermCombos,
  maliciousInfrastructure,
  lookupPackage,
  lookupDomain,
  lookupIP,
} from '../data/signatures';
import {
  getInstalledApps,
  getRunningServices,
  getNetworkConnections,
  getSystemIntegrity,
  computeFileHash,
} from '../native/NativeBridge';
import { notifyScanComplete, notifyCriticalThreat } from '../utils/notifications';
import { addScanToHistory, updateLastScan, type ScanHistoryEntry } from '../utils/scheduler';
import { generateReport, type ScanReport } from '../utils/reportExport';
import { scanFiles } from '../utils/fileScanner';

interface ScanEngineState {
  scanState: ScanSessionStatus;
  currentModuleIndex: number;
  modules: ScanModule[];
  overallProgress: number;
  results: ScanResult[];
  riskScore: RiskScore | null;
  report: ScanReport | null;
  startScan: () => void;
  resetScan: () => void;
  removeCleanedResults: (cleanedIds: string[]) => void;
}

export function useScanEngine(): ScanEngineState {
  const [scanState, setScanState] = useState<ScanSessionStatus>('idle');
  const [currentModuleIndex, setCurrentModuleIndex] = useState(-1);
  const [modules, setModules] = useState<ScanModule[]>(
    defaultModules.map((m) => ({ ...m }))
  );
  const [overallProgress, setOverallProgress] = useState(0);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [riskScore, setRiskScore] = useState<RiskScore | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const abortRef = useRef(false);
  const scanStartRef = useRef<number>(0);

  const updateModule = useCallback(
    (index: number, updates: Partial<ScanModule>) => {
      setModules((prev) => {
        const next = [...prev];
        next[index] = { ...next[index], ...updates };
        return next;
      });
    },
    []
  );

  // ─── Module 1: Permission Analysis ────────────────────────────
  const runPermissionAnalysis = useCallback(async (): Promise<ScanResult[]> => {
    const apps = await getInstalledApps();
    const findings: ScanResult[] = [];

    // Merge original combos with expanded signature combos
    const allCombos = [
      ...dangerousPermCombos,
      ...expandedDangerousPermCombos,
    ];

    // Deduplicate by permission set
    const seen = new Set<string>();
    const uniqueCombos = allCombos.filter((c) => {
      const key = [...c.permissions].sort().join('|');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    for (const app of apps) {
      if (app.isSystemApp) continue;

      const grantedPerms = app.permissions
        .filter((p) => p.granted)
        .map((p) => p.name);

      // Check for dangerous permission combinations (original + expanded)
      for (const combo of uniqueCombos) {
        const hasAllPerms = combo.permissions.every((p) => grantedPerms.includes(p));
        if (hasAllPerms) {
          const category = (combo as any).category || '';
          findings.push({
            id: `perm-${app.packageName}-${findings.length}`,
            moduleId: 'permissions',
            title: `Dangerous Permission Combination${category ? ` (${category})` : ''}`,
            description: `${app.appName}: ${combo.risk}`,
            severity: combo.severity as SeverityLevel,
            recommendation: `Review permissions for ${app.appName}. Consider revoking unnecessary permissions.`,
            timestamp: Date.now(),
            evidence: combo.permissions,
            packageName: app.packageName,
          });
        }
      }

      // Check for overprivileged apps (non-system apps with 3+ dangerous permissions)
      const dangerousPerms = app.permissions.filter(
        (p) => p.granted && (p.riskLevel === 'high' || p.riskLevel === 'critical')
      );
      if (dangerousPerms.length >= 3) {
        findings.push({
          id: `perm-overpriv-${app.packageName}`,
          moduleId: 'permissions',
          title: 'Overprivileged Application',
          description: `${app.appName} has ${dangerousPerms.length} dangerous permissions granted.`,
          severity: 'medium',
          recommendation: `Audit ${app.appName}'s permissions and revoke any that aren't essential.`,
          timestamp: Date.now(),
          evidence: dangerousPerms.map((p) => `${p.name} (${p.riskLevel})`),
          packageName: app.packageName,
        });
      }
    }

    return findings;
  }, []);

  // ─── Module 2: Behavioral Heuristics ──────────────────────────
  const runBehavioralAnalysis = useCallback(async (): Promise<ScanResult[]> => {
    const services = await getRunningServices();
    const apps = await getInstalledApps();
    const findings: ScanResult[] = [];

    // Check for suspicious background services
    for (const service of services) {
      if (service.isForeground) continue;

      const app = apps.find((a) => a.packageName === service.packageName);
      if (app && !app.isSystemApp) {
        // High memory usage background service
        if (service.memoryUsageKb > 30000) {
          findings.push({
            id: `beh-mem-${service.packageName}`,
            moduleId: 'behavior',
            title: 'High Memory Background Service',
            description: `${app.appName} is running a background service using ${Math.round(service.memoryUsageKb / 1024)}MB of memory.`,
            severity: 'medium',
            recommendation: `Force-stop ${app.appName} if you don't need it running in the background.`,
            timestamp: Date.now(),
            evidence: [
              `Service: ${service.serviceName}`,
              `Memory: ${Math.round(service.memoryUsageKb / 1024)}MB`,
              `PID: ${service.pid}`,
            ],
            packageName: service.packageName,
          });
        }

        // Service running for extended time without foreground notification
        if (service.startTime && Date.now() - service.startTime > 3600000) {
          findings.push({
            id: `beh-persist-${service.packageName}`,
            moduleId: 'behavior',
            title: 'Persistent Background Activity',
            description: `${app.appName} has been running in the background for over ${Math.round((Date.now() - service.startTime) / 3600000)} hours.`,
            severity: 'low',
            recommendation: `Review why ${app.appName} needs constant background access.`,
            timestamp: Date.now(),
            packageName: service.packageName,
          });
        }
      }
    }

    return findings;
  }, []);

  // ─── Module 3: YARA Signature Matching ────────────────────────
  const runSignatureMatching = useCallback(async (): Promise<ScanResult[]> => {
    const apps = await getInstalledApps();
    const findings: ScanResult[] = [];
    const matchedPackages = new Set<string>();

    for (const app of apps) {
      if (app.isSystemApp) continue;

      // ── Check against expanded maliciousPackagePatterns (signatures.ts) ──
      const sigMatch = lookupPackage(app.packageName);
      if (sigMatch.matched) {
        const key = `${app.packageName}-${sigMatch.family}`;
        if (!matchedPackages.has(key)) {
          matchedPackages.add(key);
          findings.push({
            id: `sig-exp-${app.packageName}-${sigMatch.family}`,
            moduleId: 'signature',
            title: `${sigMatch.family} Malware Detected`,
            description: `${app.appName} matches signature for ${sigMatch.family}: ${sigMatch.description}`,
            severity: (sigMatch.severity || 'high') as SeverityLevel,
            recommendation: `Uninstall ${app.appName} immediately. ${sigMatch.severity === 'critical' ? 'Change passwords from a clean device.' : 'Review device security.'}`,
            timestamp: Date.now(),
            evidence: [
              `Package: ${app.packageName}`,
              `Family: ${sigMatch.family}`,
              `Severity: ${sigMatch.severity}`,
              `Source: Expanded Signature DB`,
            ],
            packageName: app.packageName,
          });
        }
      }

      // ── Check against threat families (threats.ts) ──
      for (const threat of threatFamilies) {
        if (!threat.packagePatterns) continue;

        for (const pattern of threat.packagePatterns) {
          try {
            const regex = new RegExp(pattern, 'i');
            if (regex.test(app.packageName)) {
              const key = `${app.packageName}-${threat.id}`;
              if (!matchedPackages.has(key)) {
                matchedPackages.add(key);
                findings.push({
                  id: `sig-pkg-${app.packageName}-${threat.id}`,
                  moduleId: 'signature',
                  title: `${threat.name} Indicator Detected`,
                  description: `${app.appName} matches package pattern for known threat: ${threat.name} (${threat.category}).`,
                  severity: threat.severity,
                  recommendation: `Immediate removal recommended. ${threat.category === 'Banking Trojan' ? 'Change banking passwords from a clean device.' : 'Review device security.'}`,
                  timestamp: Date.now(),
                  evidence: [
                    `Package: ${app.packageName}`,
                    `Matched threat: ${threat.name}`,
                    `Category: ${threat.category}`,
                    `Known aliases: ${threat.aliases.join(', ')}`,
                  ],
                  packageName: app.packageName,
                });
              }
            }
          } catch {
            // Invalid regex, skip
          }
        }
      }

      // ── Hash-based detection ──
      if (app.apkPath) {
        const hash = await computeFileHash(app.apkPath);
        for (const threat of threatFamilies) {
          if (threat.hashSignatures?.includes(hash)) {
            findings.push({
              id: `sig-hash-${app.packageName}-${threat.id}`,
              moduleId: 'signature',
              title: `${threat.name} — Hash Match`,
              description: `APK hash for ${app.appName} matches known malicious signature.`,
              severity: 'critical',
              recommendation: 'Uninstall immediately. This is a confirmed malware match.',
              timestamp: Date.now(),
              evidence: [`SHA256: ${hash}`, `Threat: ${threat.name}`],
              packageName: app.packageName,
              hash,
            });
          }
        }
      }
    }

    return findings;
  }, []);

  // ─── Module 4: Network Profiling ──────────────────────────────
  const runNetworkProfiling = useCallback(async (): Promise<ScanResult[]> => {
    const connections = await getNetworkConnections();
    const findings: ScanResult[] = [];

    for (const conn of connections) {
      let matched = false;

      // ── Check against expanded malicious infrastructure (signatures.ts) ──
      const domainMatch = lookupDomain(conn.remoteAddress);
      const ipMatch = lookupIP(conn.remoteAddress);
      const infraMatch = domainMatch.matched ? domainMatch : ipMatch.matched ? ipMatch : null;

      if (infraMatch) {
        matched = true;
        const typeLabel = infraMatch.type === 'c2' ? 'Command & Control' :
                          infraMatch.type === 'exfil' ? 'Data Exfiltration' :
                          infraMatch.type === 'dropper' ? 'Malware Dropper' :
                          infraMatch.type === 'phishing' ? 'Phishing' : 'Malicious';

        findings.push({
          id: `net-infra-${conn.remoteAddress}-${conn.remotePort}`,
          moduleId: 'network',
          title: `${typeLabel} Server Connection`,
          description: `Active connection to known ${typeLabel.toLowerCase()} infrastructure at ${conn.remoteAddress}:${conn.remotePort}. Associated with ${infraMatch.family}.`,
          severity: 'critical',
          recommendation: `Block network access for the responsible app. Associated malware family: ${infraMatch.family}.`,
          timestamp: Date.now(),
          evidence: [
            `Remote: ${conn.remoteAddress}:${conn.remotePort}`,
            `Type: ${typeLabel}`,
            `Family: ${infraMatch.family}`,
            `Protocol: ${conn.protocol}`,
            `State: ${conn.state}`,
            conn.packageName ? `App: ${conn.packageName}` : 'Unknown app',
          ],
          packageName: conn.packageName,
        });
      }

      // ── Check against original C2 domains (threats.ts) ──
      if (!matched) {
        const isKnownC2 = knownC2Domains.some(
          (domain) =>
            conn.remoteAddress.includes(domain) ||
            conn.remoteAddress === domain
        );

        if (isKnownC2) {
          findings.push({
            id: `net-c2-${conn.remoteAddress}-${conn.remotePort}`,
            moduleId: 'network',
            title: 'C2 Server Connection Detected',
            description: `Active connection to known command-and-control server at ${conn.remoteAddress}:${conn.remotePort}.`,
            severity: 'critical',
            recommendation: 'Block network access for the responsible app and uninstall immediately.',
            timestamp: Date.now(),
            evidence: [
              `Remote: ${conn.remoteAddress}:${conn.remotePort}`,
              `Protocol: ${conn.protocol}`,
              `State: ${conn.state}`,
              conn.packageName ? `App: ${conn.packageName}` : 'Unknown app',
            ],
            packageName: conn.packageName,
          });
        }
      }

      // ── Check for unencrypted HTTP connections (port 80) ──
      if (conn.remotePort === 80 && conn.state === 'ESTABLISHED') {
        findings.push({
          id: `net-http-${conn.remoteAddress}`,
          moduleId: 'network',
          title: 'Unencrypted Connection',
          description: `Active HTTP (non-HTTPS) connection to ${conn.remoteAddress}. Data may be intercepted.`,
          severity: 'medium',
          recommendation: 'Investigate which app is sending data over unencrypted HTTP.',
          timestamp: Date.now(),
          evidence: [
            `Remote: ${conn.remoteAddress}:80`,
            `Protocol: HTTP (unencrypted)`,
            conn.packageName ? `App: ${conn.packageName}` : 'Unknown app',
          ],
          packageName: conn.packageName,
        });
      }
    }

    return findings;
  }, []);

  // ─── Module 5: System Integrity ───────────────────────────────
  const runSystemIntegrity = useCallback(async (): Promise<ScanResult[]> => {
    const integrity = await getSystemIntegrity();
    const findings: ScanResult[] = [];

    if (integrity.isRooted) {
      findings.push({
        id: 'int-root',
        moduleId: 'integrity',
        title: 'Device is Rooted',
        description: 'Root access detected. Rooted devices are significantly more vulnerable to malware.',
        severity: 'high',
        recommendation: 'Consider unrooting your device if you don\'t need root access for development.',
        timestamp: Date.now(),
        evidence: ['Root binary detected', 'su available in PATH'],
      });
    }

    if (integrity.isBootloaderUnlocked) {
      findings.push({
        id: 'int-bootloader',
        moduleId: 'integrity',
        title: 'Bootloader Unlocked',
        description: 'Unlocked bootloader allows installation of unsigned firmware.',
        severity: 'high',
        recommendation: 'Relock the bootloader if not actively developing custom ROMs.',
        timestamp: Date.now(),
      });
    }

    if (integrity.isDeveloperModeEnabled) {
      findings.push({
        id: 'int-devmode',
        moduleId: 'integrity',
        title: 'Developer Mode Enabled',
        description: 'Developer options are active, which exposes additional attack surfaces.',
        severity: 'low',
        recommendation: 'Disable Developer Options in Settings if not actively needed.',
        timestamp: Date.now(),
      });
    }

    if (integrity.isUsbDebuggingEnabled) {
      findings.push({
        id: 'int-usb',
        moduleId: 'integrity',
        title: 'USB Debugging Enabled',
        description: 'ADB access is enabled. Physical access to device could allow data extraction.',
        severity: 'medium',
        recommendation: 'Disable USB Debugging when not in active development.',
        timestamp: Date.now(),
        evidence: [
          `ADB over WiFi: ${integrity.isAdbOverWifi ? 'YES (high risk)' : 'No'}`,
        ],
      });
    }

    if (integrity.isAdbOverWifi) {
      findings.push({
        id: 'int-adb-wifi',
        moduleId: 'integrity',
        title: 'ADB Over WiFi Active',
        description: 'Wireless debugging is enabled. Any device on the same network could connect.',
        severity: 'high',
        recommendation: 'Disable wireless debugging immediately unless actively needed.',
        timestamp: Date.now(),
      });
    }

    if (!integrity.isEncrypted) {
      findings.push({
        id: 'int-encryption',
        moduleId: 'integrity',
        title: 'Device Not Encrypted',
        description: 'Device storage is not encrypted. Physical access could expose all data.',
        severity: 'critical',
        recommendation: 'Enable full device encryption in Security settings.',
        timestamp: Date.now(),
      });
    }

    if (integrity.seLinuxStatus !== 'enforcing') {
      findings.push({
        id: 'int-selinux',
        moduleId: 'integrity',
        title: 'SELinux Not Enforcing',
        description: `SELinux status: ${integrity.seLinuxStatus}. This weakens OS security boundaries.`,
        severity: 'high',
        recommendation: 'SELinux should be in enforcing mode for maximum security.',
        timestamp: Date.now(),
      });
    }

    return findings;
  }, []);

  // ─── Module 6: Adware & Stalkerware Agent ────────────────────
  const runAdwareStalkAgent = useCallback(async (): Promise<ScanResult[]> => {
    const apps = await getInstalledApps();
    const findings: ScanResult[] = [];

    for (const app of apps) {
      if (app.isSystemApp) continue;

      const grantedPerms = app.permissions
        .filter((p) => p.granted)
        .map((p) => p.name);

      // ── Stalkerware detection: GPS + Camera + Audio + Background ──
      const hasLocation = grantedPerms.some((p) => p.includes('ACCESS_FINE_LOCATION') || p.includes('ACCESS_BACKGROUND_LOCATION'));
      const hasCamera = grantedPerms.some((p) => p.includes('CAMERA'));
      const hasAudio = grantedPerms.some((p) => p.includes('RECORD_AUDIO'));
      const hasBoot = grantedPerms.some((p) => p.includes('RECEIVE_BOOT_COMPLETED'));
      const hasInternet = grantedPerms.some((p) => p.includes('INTERNET'));
      const hasAccessibility = grantedPerms.some((p) => p.includes('BIND_ACCESSIBILITY_SERVICE'));

      // Full surveillance suite detection
      if (hasLocation && hasCamera && hasAudio && hasInternet && hasBoot) {
        findings.push({
          id: `stalk-surv-${app.packageName}`,
          moduleId: 'adware',
          agentId: 'adware',
          title: 'Surveillance App Pattern Detected',
          description: `${app.appName} has GPS tracking, camera, microphone, internet, and auto-start — matching stalkerware behavior.`,
          severity: 'critical',
          confidence: 85,
          recommendation: `Uninstall ${app.appName} immediately. If you suspect domestic surveillance, contact local authorities.`,
          timestamp: Date.now(),
          evidence: [
            'GPS location tracking enabled',
            'Camera access granted',
            'Microphone recording granted',
            'Starts on device boot',
            'Internet access for data exfiltration',
          ],
          packageName: app.packageName,
        });
      }

      // Accessibility abuse (non-accessibility apps using it for keylogging)
      if (hasAccessibility && hasInternet) {
        const isLikelyAccessibility = app.packageName.includes('accessibility') ||
          app.packageName.includes('talkback') || app.packageName.includes('braille');
        if (!isLikelyAccessibility) {
          findings.push({
            id: `stalk-a11y-${app.packageName}`,
            moduleId: 'adware',
            agentId: 'adware',
            title: 'Accessibility Service Abuse',
            description: `${app.appName} uses Accessibility Service with internet access — potential keylogger or screen reader.`,
            severity: 'critical',
            confidence: 80,
            recommendation: `Disable Accessibility Service for ${app.appName} unless it genuinely needs it.`,
            timestamp: Date.now(),
            evidence: [
              'BIND_ACCESSIBILITY_SERVICE active',
              'INTERNET permission granted',
              'Not a standard accessibility tool',
            ],
            packageName: app.packageName,
          });
        }
      }

      // Aggressive ad SDK detection: SYSTEM_ALERT_WINDOW in non-utility apps
      const hasOverlay = grantedPerms.some((p) => p.includes('SYSTEM_ALERT_WINDOW'));
      if (hasOverlay && hasInternet) {
        const isLikelyLegit = app.packageName.includes('facebook') ||
          app.packageName.includes('messenger') || app.packageName.includes('bubble');
        if (!isLikelyLegit) {
          findings.push({
            id: `adware-overlay-${app.packageName}`,
            moduleId: 'adware',
            agentId: 'adware',
            title: 'Aggressive Ad Overlay Capability',
            description: `${app.appName} can display overlays on top of other apps — used by aggressive adware and phishing kits.`,
            severity: 'medium',
            confidence: 65,
            recommendation: `Revoke "Display over other apps" permission for ${app.appName}.`,
            timestamp: Date.now(),
            evidence: [
              'SYSTEM_ALERT_WINDOW permission granted',
              'INTERNET permission granted',
            ],
            packageName: app.packageName,
          });
        }
      }

      // Hidden GPS tracker: location + boot + internet, no camera/audio (silent tracker)
      if (hasLocation && hasBoot && hasInternet && !hasCamera && !hasAudio) {
        const isLikelyGPS = app.packageName.includes('maps') ||
          app.packageName.includes('navigation') || app.packageName.includes('weather') ||
          app.packageName.includes('google');
        if (!isLikelyGPS) {
          findings.push({
            id: `stalk-gps-${app.packageName}`,
            moduleId: 'adware',
            agentId: 'adware',
            title: 'Silent GPS Tracker Pattern',
            description: `${app.appName} tracks location from boot with internet access — consistent with covert GPS tracking.`,
            severity: 'high',
            confidence: 70,
            recommendation: `Review why ${app.appName} needs persistent location access. Consider revoking location permission.`,
            timestamp: Date.now(),
            evidence: [
              'ACCESS_FINE_LOCATION or BACKGROUND_LOCATION',
              'RECEIVE_BOOT_COMPLETED',
              'INTERNET access',
              'No camera/microphone (silent tracker)',
            ],
            packageName: app.packageName,
          });
        }
      }
    }

    return findings;
  }, []);

  // ─── Module 7: Data Exfiltration Agent ───────────────────────
  const runExfiltrationAgent = useCallback(async (): Promise<ScanResult[]> => {
    const apps = await getInstalledApps();
    const findings: ScanResult[] = [];

    for (const app of apps) {
      if (app.isSystemApp) continue;

      const grantedPerms = app.permissions
        .filter((p) => p.granted)
        .map((p) => p.name);

      const hasInternet = grantedPerms.some((p) => p.includes('INTERNET'));
      if (!hasInternet) continue; // Can't exfiltrate without network

      const hasContacts = grantedPerms.some((p) => p.includes('READ_CONTACTS'));
      const hasSMS = grantedPerms.some((p) => p.includes('READ_SMS') || p.includes('RECEIVE_SMS'));
      const hasCallLog = grantedPerms.some((p) => p.includes('READ_CALL_LOG'));
      const hasStorage = grantedPerms.some((p) => p.includes('READ_EXTERNAL_STORAGE') || p.includes('READ_MEDIA'));
      const hasBoot = grantedPerms.some((p) => p.includes('RECEIVE_BOOT_COMPLETED'));
      const hasPhone = grantedPerms.some((p) => p.includes('READ_PHONE_STATE'));

      // Data harvester: contacts + SMS + call log + internet
      const dataAccessCount = [hasContacts, hasSMS, hasCallLog, hasPhone].filter(Boolean).length;
      if (dataAccessCount >= 2) {
        const isLikelyLegit = app.packageName.includes('google') ||
          app.packageName.includes('samsung') || app.packageName.includes('messaging') ||
          app.packageName.includes('dialer') || app.packageName.includes('contacts');
        if (!isLikelyLegit) {
          findings.push({
            id: `exfil-harvest-${app.packageName}`,
            moduleId: 'exfiltration',
            agentId: 'exfiltration',
            title: 'Data Harvesting Pattern',
            description: `${app.appName} can access ${dataAccessCount} sensitive data sources (contacts, SMS, call logs, phone state) and transmit them via internet.`,
            severity: dataAccessCount >= 3 ? 'critical' : 'high',
            confidence: 75,
            recommendation: `Review ${app.appName}'s permissions. Consider revoking access to contacts, SMS, and call logs unless essential.`,
            timestamp: Date.now(),
            evidence: [
              hasContacts ? 'READ_CONTACTS granted' : null,
              hasSMS ? 'READ_SMS / RECEIVE_SMS granted' : null,
              hasCallLog ? 'READ_CALL_LOG granted' : null,
              hasPhone ? 'READ_PHONE_STATE granted' : null,
              'INTERNET access for transmission',
            ].filter(Boolean) as string[],
            packageName: app.packageName,
          });
        }
      }

      // Persistent file exfiltration: storage + internet + boot
      if (hasStorage && hasInternet && hasBoot) {
        const isLikelyLegit = app.packageName.includes('google') ||
          app.packageName.includes('cloud') || app.packageName.includes('backup') ||
          app.packageName.includes('photos');
        if (!isLikelyLegit) {
          findings.push({
            id: `exfil-files-${app.packageName}`,
            moduleId: 'exfiltration',
            agentId: 'exfiltration',
            title: 'Persistent File Access',
            description: `${app.appName} can read device files, has internet access, and starts on boot — file exfiltration pattern.`,
            severity: 'high',
            confidence: 65,
            recommendation: `Revoke storage permission for ${app.appName} if it doesn't need file access.`,
            timestamp: Date.now(),
            evidence: [
              'READ_EXTERNAL_STORAGE or READ_MEDIA granted',
              'INTERNET access for data upload',
              'RECEIVE_BOOT_COMPLETED for persistence',
            ],
            packageName: app.packageName,
          });
        }
      }

      // SMS + Contacts data scrape (social graph theft)
      if (hasContacts && hasSMS && hasInternet) {
        const isLikelyLegit = app.packageName.includes('whatsapp') ||
          app.packageName.includes('telegram') || app.packageName.includes('signal') ||
          app.packageName.includes('messaging') || app.packageName.includes('google');
        if (!isLikelyLegit) {
          findings.push({
            id: `exfil-social-${app.packageName}`,
            moduleId: 'exfiltration',
            agentId: 'exfiltration',
            title: 'Social Graph Scraping',
            description: `${app.appName} can read both contacts and SMS messages — enables full social graph mapping.`,
            severity: 'high',
            confidence: 70,
            recommendation: `This combination allows mapping your entire social network. Review if ${app.appName} genuinely needs both permissions.`,
            timestamp: Date.now(),
            evidence: [
              'READ_CONTACTS — access to contact list',
              'READ_SMS — access to message content',
              'INTERNET — ability to transmit harvested data',
            ],
            packageName: app.packageName,
          });
        }
      }
    }

    return findings;
  }, []);

  // ─── Module 8: Cryptojacking & Fraud Agent ───────────────────
  const runFraudAgent = useCallback(async (): Promise<ScanResult[]> => {
    const apps = await getInstalledApps();
    const services = await getRunningServices();
    const findings: ScanResult[] = [];

    // ── Check for premium SMS fraud ──
    for (const app of apps) {
      if (app.isSystemApp) continue;

      const grantedPerms = app.permissions
        .filter((p) => p.granted)
        .map((p) => p.name);

      const canSendSMS = grantedPerms.some((p) => p.includes('SEND_SMS'));
      const hasInternet = grantedPerms.some((p) => p.includes('INTERNET'));

      // SMS fraud: SEND_SMS in non-messaging apps
      if (canSendSMS) {
        const isLikelyMessenger = app.packageName.includes('messaging') ||
          app.packageName.includes('sms') || app.packageName.includes('mms') ||
          app.packageName.includes('dialer') || app.packageName.includes('google.android.apps') ||
          app.packageName.includes('samsung');
        if (!isLikelyMessenger) {
          findings.push({
            id: `fraud-sms-${app.packageName}`,
            moduleId: 'fraud',
            agentId: 'fraud',
            title: 'Premium SMS Fraud Risk',
            description: `${app.appName} can send SMS messages without being a messaging app — premium SMS subscription fraud pattern.`,
            severity: 'high',
            confidence: 75,
            recommendation: `Revoke SEND_SMS permission for ${app.appName}. This permission enables premium SMS charges.`,
            timestamp: Date.now(),
            evidence: [
              'SEND_SMS permission granted',
              'Not a recognized messaging app',
              `Package: ${app.packageName}`,
            ],
            packageName: app.packageName,
          });
        }
      }

      // Toll fraud: CALL_PHONE in non-dialer apps
      const canCall = grantedPerms.some((p) => p.includes('CALL_PHONE'));
      if (canCall) {
        const isLikelyDialer = app.packageName.includes('dialer') ||
          app.packageName.includes('phone') || app.packageName.includes('contacts') ||
          app.packageName.includes('google') || app.packageName.includes('samsung');
        if (!isLikelyDialer) {
          findings.push({
            id: `fraud-toll-${app.packageName}`,
            moduleId: 'fraud',
            agentId: 'fraud',
            title: 'Toll Fraud Risk',
            description: `${app.appName} can make phone calls directly — potential toll fraud or premium number dialing.`,
            severity: 'medium',
            confidence: 60,
            recommendation: `Revoke CALL_PHONE permission for ${app.appName} unless it needs calling functionality.`,
            timestamp: Date.now(),
            evidence: [
              'CALL_PHONE permission granted',
              'Not a recognized dialer/phone app',
            ],
            packageName: app.packageName,
          });
        }
      }

      // Dropper capability: can install other APKs
      const canInstall = grantedPerms.some((p) => p.includes('REQUEST_INSTALL_PACKAGES'));
      if (canInstall && hasInternet) {
        const isLikelyStore = app.packageName.includes('vending') ||
          app.packageName.includes('store') || app.packageName.includes('market') ||
          app.packageName.includes('fdroid') || app.packageName.includes('aurora');
        if (!isLikelyStore) {
          findings.push({
            id: `fraud-dropper-${app.packageName}`,
            moduleId: 'fraud',
            agentId: 'fraud',
            title: 'Dropper / Sideload Capability',
            description: `${app.appName} can download and install additional APKs — malware dropper pattern.`,
            severity: 'high',
            confidence: 70,
            recommendation: `Revoke "Install unknown apps" permission for ${app.appName}. Droppers install additional malware.`,
            timestamp: Date.now(),
            evidence: [
              'REQUEST_INSTALL_PACKAGES granted',
              'INTERNET access for APK download',
              'Not a recognized app store',
            ],
            packageName: app.packageName,
          });
        }
      }
    }

    // ── Check for crypto mining: high-memory background services ──
    for (const service of services) {
      if (service.isForeground) continue;
      const app = apps.find((a) => a.packageName === service.packageName);
      if (!app || app.isSystemApp) continue;

      // Crypto mining indicator: very high memory in background
      if (service.memoryUsageKb > 50000) {
        findings.push({
          id: `fraud-mine-${service.packageName}-${service.pid}`,
          moduleId: 'fraud',
          agentId: 'fraud',
          title: 'Potential Cryptojacking',
          description: `${app.appName} is consuming ${Math.round(service.memoryUsageKb / 1024)}MB in background — consistent with cryptocurrency mining.`,
          severity: 'high',
          confidence: 55,
          recommendation: `Force-stop ${app.appName} and monitor battery drain. High background memory usage often indicates crypto mining.`,
          timestamp: Date.now(),
          evidence: [
            `Service: ${service.serviceName}`,
            `Memory: ${Math.round(service.memoryUsageKb / 1024)}MB`,
            `PID: ${service.pid}`,
            'Running in background without foreground notification',
          ],
          packageName: service.packageName,
        });
      }
    }

    return findings;
  }, []);

  // ─── Module 9: File & Media Scanner ────────────────────────────
  const runFileScanner = useCallback(async (): Promise<ScanResult[]> => {
    return new Promise((resolve, reject) => {
      // Run the file scanner and capture the final results
      scanFiles(undefined, (progress) => {
        // We could theoretically update the module progress here, 
        // but the main engine simulates 0-100% loop anyway.
      })
      .then(resolve)
      .catch(reject);
    });
  }, []);

  // ─── Cross-Agent Correlation Engine ──────────────────────────
  const correlateFindings = useCallback((allResults: ScanResult[]): ScanResult[] => {
    // Group findings by package name
    const byPackage: Record<string, ScanResult[]> = {};
    for (const result of allResults) {
      if (!result.packageName) continue;
      if (!byPackage[result.packageName]) byPackage[result.packageName] = [];
      byPackage[result.packageName].push(result);
    }

    const correlatedFindings: ScanResult[] = [];

    for (const [pkg, pkgFindings] of Object.entries(byPackage)) {
      // Get unique agent/module IDs that flagged this package
      const agentIds = [...new Set(pkgFindings.map((r) => r.moduleId))];

      if (agentIds.length >= 2) {
        // Multiple agents agree — create correlated finding
        const maxSeverity = pkgFindings.reduce<SeverityLevel>((max, r) => {
          const order: SeverityLevel[] = ['safe', 'low', 'medium', 'high', 'critical'];
          return order.indexOf(r.severity) > order.indexOf(max) ? r.severity : max;
        }, 'safe');

        // Boost severity if 3+ agents agree
        const boostedSeverity: SeverityLevel =
          agentIds.length >= 3 ? 'critical' :
          maxSeverity === 'high' ? 'critical' :
          maxSeverity === 'medium' ? 'high' :
          maxSeverity;

        // Calculate cross-agent confidence
        const avgConfidence = pkgFindings.reduce((sum, r) => sum + (r.confidence || 50), 0) / pkgFindings.length;
        const correlatedConfidence = Math.min(99, Math.round(avgConfidence + agentIds.length * 8));

        const appName = pkgFindings[0].description.match(/^([^:]+)/)?.[1] || pkg;

        correlatedFindings.push({
          id: `corr-${pkg}`,
          moduleId: 'correlation',
          agentId: 'correlation',
          title: `Cross-Agent Alert: ${appName}`,
          description: `${agentIds.length} independent agents flagged ${pkg}. Combined evidence strongly suggests malicious behavior.`,
          severity: boostedSeverity,
          confidence: correlatedConfidence,
          correlated: true,
          correlatedAgents: agentIds,
          recommendation: `HIGH PRIORITY — Multiple analysis engines independently identified ${appName} as suspicious. Uninstall recommended.`,
          timestamp: Date.now(),
          evidence: [
            `Flagged by ${agentIds.length} agents: ${agentIds.join(', ')}`,
            `Total findings: ${pkgFindings.length}`,
            `Original max severity: ${maxSeverity}`,
            `Boosted severity: ${boostedSeverity}`,
            `Cross-agent confidence: ${correlatedConfidence}%`,
            ...pkgFindings.slice(0, 5).map((f) => `[${f.moduleId}] ${f.title}`),
          ],
          packageName: pkg,
        });
      }
    }

    return correlatedFindings;
  }, []);

  // ─── Calculate Risk Score ─────────────────────────────────────
  const calculateRiskScore = useCallback((allResults: ScanResult[]): RiskScore => {
    const scoreByModule: Record<string, number> = {
      permissions: 0,
      behavior: 0,
      signatures: 0,
      network: 0,
      integrity: 0,
      adware: 0,
      exfiltration: 0,
      fraud: 0,
    };

    const severityWeight: Record<string, number> = {
      safe: 0,
      low: 5,
      medium: 15,
      high: 30,
      critical: 50,
    };

    for (const result of allResults) {
      const weight = severityWeight[result.severity] || 0;
      if (scoreByModule[result.moduleId] !== undefined) {
        scoreByModule[result.moduleId] = Math.min(
          100,
          scoreByModule[result.moduleId] + weight
        );
      }
    }

    const overall = Math.min(
      100,
      Math.round(
        Object.values(scoreByModule).reduce((sum, s) => sum + s, 0) /
          Object.keys(scoreByModule).length
      )
    );

    const level: SeverityLevel =
      overall >= 75
        ? 'critical'
        : overall >= 50
        ? 'high'
        : overall >= 25
        ? 'medium'
        : overall > 0
        ? 'low'
        : 'safe';

    const criticalCount = allResults.filter(
      (r) => r.severity === 'critical'
    ).length;
    const highCount = allResults.filter((r) => r.severity === 'high').length;

    let summary = '';
    if (criticalCount > 0) {
      summary = `${criticalCount} critical threat${criticalCount > 1 ? 's' : ''} detected. Immediate action recommended.`;
    } else if (highCount > 0) {
      summary = `${highCount} high-risk issue${highCount > 1 ? 's' : ''} found. Review recommended.`;
    } else if (allResults.length > 0) {
      summary = `${allResults.length} finding${allResults.length > 1 ? 's' : ''} detected. Minor risks identified.`;
    } else {
      summary = 'No threats detected. Your device appears secure.';
    }

    return {
      overall,
      breakdown: {
        permissions: scoreByModule.permissions,
        behavior: scoreByModule.behavior,
        signatures: scoreByModule.signatures,
        network: scoreByModule.network,
        integrity: scoreByModule.integrity,
        adware: scoreByModule.adware,
        exfiltration: scoreByModule.exfiltration,
        fraud: scoreByModule.fraud,
      },
      level,
      summary,
    };
  }, []);

  // ─── Main Scan Pipeline ───────────────────────────────────────
  const startScan = useCallback(async () => {
    abortRef.current = false;
    scanStartRef.current = Date.now();
    setScanState('running');
    setResults([]);
    setRiskScore(null);
    setReport(null);
    setOverallProgress(0);
    setCurrentModuleIndex(0);

    // Reset all modules
    const freshModules = defaultModules.map((m) => ({
      ...m,
      status: 'queued' as const,
      findingsCount: 0,
      progress: 0,
    }));
    setModules(freshModules);

    const allResults: ScanResult[] = [];

    const scanFunctions = [
      runPermissionAnalysis,
      runBehavioralAnalysis,
      runSignatureMatching,
      runNetworkProfiling,
      runSystemIntegrity,
      runAdwareStalkAgent,
      runExfiltrationAgent,
      runFraudAgent,
      runFileScanner,
    ];

    for (let i = 0; i < scanFunctions.length; i++) {
      if (abortRef.current) {
        setScanState('aborted');
        return;
      }

      setCurrentModuleIndex(i);
      updateModule(i, { status: 'scanning', progress: 0 });

      // Simulate progressive scanning with progress updates
      for (let p = 0; p <= 80; p += 20) {
        if (abortRef.current) break;
        updateModule(i, { progress: p });
        setOverallProgress(Math.round(((i * 100 + p) / (scanFunctions.length * 100)) * 100));
        await new Promise((resolve) => setTimeout(resolve, 300));
      }

      try {
        const moduleResults = await scanFunctions[i]();
        allResults.push(...moduleResults);

        updateModule(i, {
          status: 'complete',
          progress: 100,
          findingsCount: moduleResults.length,
        });
      } catch (err) {
        console.error(`Module ${i} error:`, err);
        updateModule(i, { status: 'error', progress: 100 });
      }

      setResults([...allResults]);
      setOverallProgress(Math.round(((i + 1) / scanFunctions.length) * 100));
    }

    // ── Cross-Agent Correlation ──────────────────────────────
    const correlated = correlateFindings(allResults);
    if (correlated.length > 0) {
      // Insert correlated findings at the top of results
      allResults.unshift(...correlated);
      setResults([...allResults]);
    }

    // Calculate final risk score
    const score = calculateRiskScore(allResults);
    setRiskScore(score);
    setScanState('complete');
    setCurrentModuleIndex(-1);

    // ── Post-scan: notifications, history, report ──────────────
    try {
      // Send push notification with scan results
      await notifyScanComplete(score, allResults);

      // Send critical threat alerts for any critical findings
      const criticalResults = allResults.filter((r) => r.severity === 'critical');
      for (const critical of criticalResults.slice(0, 3)) {
        await notifyCriticalThreat(critical);
      }
    } catch (err) {
      console.warn('[ScanEngine] Notification error:', err);
    }

    try {
      // Persist scan to history
      const historyEntry: ScanHistoryEntry = {
        id: `scan-${Date.now()}`,
        timestamp: Date.now(),
        riskScore: score.overall,
        riskLevel: score.level,
        findingsCount: allResults.length,
        criticalCount: allResults.filter((r) => r.severity === 'critical').length,
        highCount: allResults.filter((r) => r.severity === 'high').length,
        duration: Date.now() - scanStartRef.current,
        modulesRun: freshModules.map((m) => m.id),
      };
      await addScanToHistory(historyEntry);
      await updateLastScan();
    } catch (err) {
      console.warn('[ScanEngine] History persistence error:', err);
    }

    // Generate exportable report
    const scanReport = generateReport(
      freshModules,
      allResults,
      score,
      scanStartRef.current
    );
    setReport(scanReport);
  }, [
    runPermissionAnalysis,
    runBehavioralAnalysis,
    runSignatureMatching,
    runNetworkProfiling,
    runSystemIntegrity,
    runAdwareStalkAgent,
    runExfiltrationAgent,
    runFraudAgent,
    correlateFindings,
    calculateRiskScore,
    updateModule,
  ]);

  const resetScan = useCallback(() => {
    abortRef.current = true;
    setScanState('idle');
    setCurrentModuleIndex(-1);
    setModules(defaultModules.map((m) => ({ ...m })));
    setOverallProgress(0);
    setResults([]);
    setRiskScore(null);
    setReport(null);
  }, []);

  const removeCleanedResults = useCallback((cleanedIds: string[]) => {
    setResults((prev) => prev.filter((r) => !cleanedIds.includes(r.id)));
  }, []);

  return {
    scanState,
    currentModuleIndex,
    modules,
    overallProgress,
    results,
    riskScore,
    report,
    startScan,
    resetScan,
    removeCleanedResults,
  };
}
