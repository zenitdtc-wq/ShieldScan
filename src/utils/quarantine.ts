/**
 * ShieldScan — Quarantine Management
 *
 * Manages quarantined threats in AsyncStorage.
 * Actions: quarantine, deep clean, restore.
 * No root required — uses system intents for uninstall.
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import type { ScanResult, SeverityLevel } from '../types/engine';

const QUARANTINE_KEY = '@shieldscan_quarantine';

// ─── Types ──────────────────────────────────────────────────────

export interface QuarantineEntry {
  id: string;
  resultId: string;
  packageName: string;
  appName: string;
  title: string;
  severity: SeverityLevel;
  moduleId: string;
  quarantinedAt: number;
  action: 'quarantine' | 'deep_clean' | 'deleted';
  status: 'pending' | 'completed' | 'failed';
  evidence: string[];
  recommendation: string;
}

// ─── Core Operations ────────────────────────────────────────────

/**
 * Get all quarantined items.
 */
export async function getQuarantine(): Promise<QuarantineEntry[]> {
  try {
    const raw = await AsyncStorage.getItem(QUARANTINE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

/**
 * Add a scan finding to quarantine.
 */
export async function quarantineThreat(
  result: ScanResult,
  appName?: string,
): Promise<QuarantineEntry> {
  const entries = await getQuarantine();

  // Don't double-quarantine
  const existing = entries.find((e) => e.resultId === result.id);
  if (existing) return existing;

  const entry: QuarantineEntry = {
    id: `q-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    resultId: result.id,
    packageName: result.packageName || 'unknown',
    appName: appName || result.packageName || 'Unknown App',
    title: result.title,
    severity: result.severity,
    moduleId: result.moduleId,
    quarantinedAt: Date.now(),
    action: 'quarantine',
    status: 'completed',
    evidence: result.evidence || [],
    recommendation: result.recommendation,
  };

  entries.unshift(entry);
  await AsyncStorage.setItem(QUARANTINE_KEY, JSON.stringify(entries));
  return entry;
}

/**
 * Mark a finding for deep clean (tracks permission revocation + uninstall request).
 */
export async function deepCleanThreat(
  result: ScanResult,
  appName?: string,
): Promise<QuarantineEntry> {
  const entries = await getQuarantine();

  // Update if already quarantined
  const existingIdx = entries.findIndex((e) => e.resultId === result.id);
  if (existingIdx >= 0) {
    entries[existingIdx].action = 'deep_clean';
    entries[existingIdx].status = 'pending';
    await AsyncStorage.setItem(QUARANTINE_KEY, JSON.stringify(entries));
    return entries[existingIdx];
  }

  const entry: QuarantineEntry = {
    id: `dc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    resultId: result.id,
    packageName: result.packageName || 'unknown',
    appName: appName || result.packageName || 'Unknown App',
    title: result.title,
    severity: result.severity,
    moduleId: result.moduleId,
    quarantinedAt: Date.now(),
    action: 'deep_clean',
    status: 'pending',
    evidence: result.evidence || [],
    recommendation: result.recommendation,
  };

  entries.unshift(entry);
  await AsyncStorage.setItem(QUARANTINE_KEY, JSON.stringify(entries));
  return entry;
}

/**
 * Mark a quarantine entry as deleted (after user confirmed uninstall).
 */
export async function markDeleted(quarantineId: string): Promise<void> {
  const entries = await getQuarantine();
  const idx = entries.findIndex((e) => e.id === quarantineId);
  if (idx >= 0) {
    entries[idx].action = 'deleted';
    entries[idx].status = 'completed';
    await AsyncStorage.setItem(QUARANTINE_KEY, JSON.stringify(entries));
  }
}

/**
 * Remove an entry from quarantine (restore/dismiss).
 */
export async function removeFromQuarantine(quarantineId: string): Promise<void> {
  const entries = await getQuarantine();
  const filtered = entries.filter((e) => e.id !== quarantineId);
  await AsyncStorage.setItem(QUARANTINE_KEY, JSON.stringify(filtered));
}

/**
 * Clear all quarantine entries.
 */
export async function clearQuarantine(): Promise<void> {
  await AsyncStorage.removeItem(QUARANTINE_KEY);
}

/**
 * Get quarantine statistics.
 */
export async function getQuarantineStats(): Promise<{
  total: number;
  pending: number;
  completed: number;
  critical: number;
}> {
  const entries = await getQuarantine();
  return {
    total: entries.length,
    pending: entries.filter((e) => e.status === 'pending').length,
    completed: entries.filter((e) => e.status === 'completed').length,
    critical: entries.filter((e) => e.severity === 'critical').length,
  };
}
