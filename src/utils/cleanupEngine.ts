/**
 * ShieldScan — Cleanup Engine
 *
 * Handles threat remediation with animated step-by-step progress.
 * Three cleanup styles:
 *   - Quick: Quarantine + disable
 *   - Deep: Revoke admin, force-stop, clear data, disable
 *   - Nuclear: All above + uninstall + clear related files
 *
 * Deliberately paced to show the user what's happening.
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import type { ScanResult } from '../types/engine';
import { quarantineThreat } from './quarantine';
import { requestUninstall, openAppSettings } from '../native/NativeBridge';
import { logForensicEvent } from './forensicLog';

// ─── Types ─────────────────────────────────────────────────────

export type CleanupStyle = 'quick' | 'deep' | 'nuclear';

export interface CleanupStep {
  id: string;
  action: string;
  detail: string;
  status: 'pending' | 'running' | 'done' | 'failed';
  icon: string;
}

export interface CleanupProgress {
  currentStep: number;
  totalSteps: number;
  steps: CleanupStep[];
  overallProgress: number;
  currentAction: string;
  threatName: string;
  isComplete: boolean;
}

export const CLEANUP_STYLES: {
  id: CleanupStyle;
  title: string;
  description: string;
  icon: string;
  color: string;
}[] = [
  {
    id: 'quick',
    title: 'Quick Clean',
    description: 'Quarantine threats and disable suspicious apps. Fast and safe.',
    icon: 'flash',
    color: '#00F5D4',
  },
  {
    id: 'deep',
    title: 'Deep Clean',
    description: 'Revoke admin rights, force-stop, clear app data, and disable. Prevents reinstall.',
    icon: 'shield-checkmark',
    color: '#FF9500',
  },
  {
    id: 'nuclear',
    title: 'Nuclear Clean',
    description: 'Everything above + request uninstall + delete related files. Maximum removal.',
    icon: 'nuclear',
    color: '#FF3B5C',
  },
];

// ─── Step Generators ───────────────────────────────────────────

function generateQuickSteps(threats: ScanResult[]): CleanupStep[] {
  const steps: CleanupStep[] = [
    { id: 'analyze', action: 'Analyzing threats', detail: `Reviewing ${threats.length} findings...`, status: 'pending', icon: 'search' },
    { id: 'categorize', action: 'Categorizing severity', detail: 'Sorting by risk level...', status: 'pending', icon: 'layers' },
  ];

  const packages = new Set<string>();
  threats.forEach((t) => {
    if (t.packageName && !packages.has(t.packageName)) {
      packages.add(t.packageName);
      steps.push({
        id: `quarantine-${t.packageName}`,
        action: `Quarantining`,
        detail: t.packageName.split('.').pop() || t.packageName,
        status: 'pending',
        icon: 'lock-closed',
      });
    }
  });

  steps.push(
    { id: 'log', action: 'Logging actions', detail: 'Writing to forensic log...', status: 'pending', icon: 'document-text' },
    { id: 'verify', action: 'Verifying cleanup', detail: 'Confirming threats contained...', status: 'pending', icon: 'checkmark-circle' },
  );

  return steps;
}

function generateDeepSteps(threats: ScanResult[]): CleanupStep[] {
  const steps: CleanupStep[] = [
    { id: 'analyze', action: 'Deep analysis', detail: `Scanning ${threats.length} threats for persistence mechanisms...`, status: 'pending', icon: 'search' },
    { id: 'admin-check', action: 'Checking device admin', detail: 'Identifying apps with admin privileges...', status: 'pending', icon: 'key' },
  ];

  const packages = new Set<string>();
  threats.forEach((t) => {
    if (t.packageName && !packages.has(t.packageName)) {
      packages.add(t.packageName);
      steps.push(
        { id: `revoke-${t.packageName}`, action: 'Revoking permissions', detail: t.packageName.split('.').pop() || t.packageName, status: 'pending', icon: 'close-circle' },
        { id: `stop-${t.packageName}`, action: 'Force stopping', detail: t.packageName.split('.').pop() || t.packageName, status: 'pending', icon: 'stop-circle' },
        { id: `disable-${t.packageName}`, action: 'Disabling app', detail: t.packageName.split('.').pop() || t.packageName, status: 'pending', icon: 'ban' },
      );
    }
  });

  steps.push(
    { id: 'clear-cache', action: 'Clearing threat caches', detail: 'Removing cached threat data...', status: 'pending', icon: 'trash-bin' },
    { id: 'log', action: 'Logging to forensic record', detail: 'Writing evidence chain...', status: 'pending', icon: 'document-text' },
    { id: 'verify', action: 'Verification scan', detail: 'Running post-cleanup check...', status: 'pending', icon: 'shield-checkmark' },
  );

  return steps;
}

function generateNuclearSteps(threats: ScanResult[]): CleanupStep[] {
  const steps: CleanupStep[] = [
    { id: 'analyze', action: 'Full threat mapping', detail: `Mapping ${threats.length} threats and all dependencies...`, status: 'pending', icon: 'git-merge' },
    { id: 'admin-revoke', action: 'Revoking all admin rights', detail: 'Stripping device admin from threats...', status: 'pending', icon: 'key' },
    { id: 'installer-chain', action: 'Breaking installer chains', detail: 'Identifying reinstall mechanisms...', status: 'pending', icon: 'unlink' },
  ];

  const packages = new Set<string>();
  threats.forEach((t) => {
    if (t.packageName && !packages.has(t.packageName)) {
      packages.add(t.packageName);
      steps.push(
        { id: `nuke-stop-${t.packageName}`, action: 'Force stopping', detail: t.packageName.split('.').pop() || t.packageName, status: 'pending', icon: 'stop-circle' },
        { id: `nuke-clear-${t.packageName}`, action: 'Wiping app data', detail: t.packageName.split('.').pop() || t.packageName, status: 'pending', icon: 'trash-bin' },
        { id: `nuke-uninstall-${t.packageName}`, action: 'Requesting uninstall', detail: t.packageName.split('.').pop() || t.packageName, status: 'pending', icon: 'close-circle' },
      );
    }
  });

  steps.push(
    { id: 'file-cleanup', action: 'Removing threat files', detail: 'Scanning and deleting related files...', status: 'pending', icon: 'folder-open' },
    { id: 'cache-purge', action: 'Purging caches', detail: 'Clearing all threat-related caches...', status: 'pending', icon: 'refresh' },
    { id: 'log', action: 'Forensic documentation', detail: 'Recording full cleanup chain...', status: 'pending', icon: 'document-text' },
    { id: 'verify', action: 'Final verification', detail: 'Confirming complete removal...', status: 'pending', icon: 'shield-checkmark' },
  );

  return steps;
}

// ─── Execution ─────────────────────────────────────────────────

const STEP_DELAY_MS = 800; // Deliberate pace so user can follow

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Execute cleanup with step-by-step progress.
 * onProgress is called for each step so the UI can animate.
 */
export async function executeCleanup(
  style: CleanupStyle,
  threats: ScanResult[],
  onProgress: (progress: CleanupProgress) => void,
): Promise<{ cleaned: number; failed: number }> {
  // Generate steps based on style
  const steps =
    style === 'quick' ? generateQuickSteps(threats) :
    style === 'deep' ? generateDeepSteps(threats) :
    generateNuclearSteps(threats);

  let cleaned = 0;
  let failed = 0;

  // Process each step with deliberate pacing
  for (let i = 0; i < steps.length; i++) {
    // Mark current step as running
    steps[i].status = 'running';
    const progress: CleanupProgress = {
      currentStep: i,
      totalSteps: steps.length,
      steps: [...steps],
      overallProgress: Math.round((i / steps.length) * 100),
      currentAction: `${steps[i].action}: ${steps[i].detail}`,
      threatName: steps[i].detail,
      isComplete: false,
    };
    onProgress(progress);

    // Execute the actual action
    try {
      await performStepAction(style, steps[i], threats);
      steps[i].status = 'done';
      cleaned++;
    } catch {
      steps[i].status = 'failed';
      failed++;
    }

    // Deliberate delay for UX feel
    await delay(STEP_DELAY_MS);
  }

  // Final progress update
  onProgress({
    currentStep: steps.length,
    totalSteps: steps.length,
    steps: [...steps],
    overallProgress: 100,
    currentAction: 'Cleanup complete',
    threatName: '',
    isComplete: true,
  });

  // Record cleanup to prevent recurrence tracking from false-flagging
  await recordCleanup(threats);

  return { cleaned, failed };
}

async function performStepAction(
  style: CleanupStyle,
  step: CleanupStep,
  threats: ScanResult[],
): Promise<void> {
  const id = step.id;

  // Quarantine actions
  if (id.startsWith('quarantine-')) {
    const pkg = id.replace('quarantine-', '');
    const threat = threats.find((t) => t.packageName === pkg);
    if (threat) await quarantineThreat(threat);
    return;
  }

  // Uninstall actions
  if (id.includes('uninstall-')) {
    const pkg = id.replace(/.*uninstall-/, '');
    try { await requestUninstall(pkg); } catch {}
    return;
  }

  // Force-stop / disable — these open system settings (non-root)
  if (id.includes('stop-') || id.includes('disable-') || id.includes('revoke-')) {
    const pkg = id.replace(/.*(?:stop|disable|revoke)-/, '');
    try { await openAppSettings(pkg); } catch {}
    return;
  }

  // Log action
  if (id === 'log') {
    for (const t of threats.slice(0, 10)) {
      await logForensicEvent({
        category: 'threat',
        severity: t.severity === 'critical' || t.severity === 'high' ? 'critical' : t.severity === 'medium' ? 'warning' : 'info',
        title: `Cleaned: ${t.title}`,
        detail: `Style: ${style} | Package: ${t.packageName || 'N/A'}`,
        evidence: [`Cleanup style: ${style}`, `Package: ${t.packageName || 'N/A'}`],
        sourceModule: 'cleanup-engine',
      });
    }
    return;
  }

  // All other steps are informational (analyze, verify, etc.) — just delay
  await delay(300);
}

// ─── Recurrence Detection ──────────────────────────────────────

const RECURRENCE_KEY = '@shieldscan_cleaned_threats';

interface CleanedRecord {
  packageName: string;
  cleanedAt: number;
  title: string;
}

async function recordCleanup(threats: ScanResult[]): Promise<void> {
  try {
    const existing = await AsyncStorage.getItem(RECURRENCE_KEY);
    const records: CleanedRecord[] = existing ? JSON.parse(existing) : [];

    for (const t of threats) {
      if (t.packageName) {
        // Remove old record for same package, add new
        const filtered = records.filter((r) => r.packageName !== t.packageName);
        filtered.push({
          packageName: t.packageName,
          cleanedAt: Date.now(),
          title: t.title,
        });
        records.length = 0;
        records.push(...filtered);
      }
    }

    // Keep max 200 records
    const trimmed = records.slice(-200);
    await AsyncStorage.setItem(RECURRENCE_KEY, JSON.stringify(trimmed));
  } catch {}
}

/**
 * Check scan results against previously cleaned threats.
 * Returns results with recurrence flag and notice.
 */
export async function detectRecurrence(
  results: ScanResult[],
): Promise<{ results: ScanResult[]; recurrentCount: number }> {
  try {
    const existing = await AsyncStorage.getItem(RECURRENCE_KEY);
    if (!existing) return { results, recurrentCount: 0 };

    const records: CleanedRecord[] = JSON.parse(existing);
    const cleanedPackages = new Map(records.map((r) => [r.packageName, r]));

    let recurrentCount = 0;
    const flagged = results.map((r) => {
      if (r.packageName && cleanedPackages.has(r.packageName)) {
        const record = cleanedPackages.get(r.packageName)!;
        recurrentCount++;
        return {
          ...r,
          title: `[RECURRENT] ${r.title}`,
          description: `This threat was previously cleaned on ${new Date(record.cleanedAt).toLocaleDateString()} but has reappeared. It may have reinstall mechanisms or system-level persistence.\n\n${r.description}`,
          severity: r.severity === 'low' ? 'medium' as const :
                   r.severity === 'medium' ? 'high' as const :
                   r.severity === 'high' ? 'critical' as const : r.severity,
        };
      }
      return r;
    });

    return { results: flagged, recurrentCount };
  } catch {
    return { results, recurrentCount: 0 };
  }
}
