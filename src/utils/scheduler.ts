/**
 * ShieldScan Scan Scheduler
 *
 * Manages recurring scan schedules using:
 * - AsyncStorage for persistence
 * - Expo Notifications for reminders
 * - Background task registration
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import {
  scheduleNextScanReminder,
  cancelScheduledScanReminders,
  scheduleDailyDigest,
} from './notifications';

const SCHEDULE_KEY = '@shieldscan_schedule';
const HISTORY_KEY = '@shieldscan_scan_history';

// ─── Schedule Types ─────────────────────────────────────────────
export type ScheduleFrequency = 'manual' | 'daily' | 'weekly' | 'biweekly' | 'monthly';

export interface ScanSchedule {
  frequency: ScheduleFrequency;
  enabled: boolean;
  preferredHour: number; // 0-23
  lastScanTimestamp: number | null;
  nextScanTimestamp: number | null;
  notificationId: string | null;
  dailyDigestEnabled: boolean;
  dailyDigestHour: number;
}

export interface ScanHistoryEntry {
  id: string;
  timestamp: number;
  riskScore: number;
  riskLevel: string;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  duration: number; // ms
  modulesRun: string[];
}

const defaultSchedule: ScanSchedule = {
  frequency: 'weekly',
  enabled: false,
  preferredHour: 9,
  lastScanTimestamp: null,
  nextScanTimestamp: null,
  notificationId: null,
  dailyDigestEnabled: false,
  dailyDigestHour: 9,
};

// ─── Schedule Management ────────────────────────────────────────

export async function getSchedule(): Promise<ScanSchedule> {
  try {
    const stored = await AsyncStorage.getItem(SCHEDULE_KEY);
    if (stored) {
      return { ...defaultSchedule, ...JSON.parse(stored) };
    }
  } catch (err) {
    console.warn('[Scheduler] Failed to read schedule:', err);
  }
  return defaultSchedule;
}

export async function saveSchedule(schedule: ScanSchedule): Promise<void> {
  try {
    await AsyncStorage.setItem(SCHEDULE_KEY, JSON.stringify(schedule));
  } catch (err) {
    console.warn('[Scheduler] Failed to save schedule:', err);
  }
}

export async function enableSchedule(
  frequency: ScheduleFrequency,
  preferredHour: number = 9
): Promise<ScanSchedule> {
  const intervalHours = frequencyToHours(frequency);

  let notificationId: string | null = null;
  if (intervalHours > 0) {
    notificationId = await scheduleNextScanReminder(intervalHours);
  }

  const nextTimestamp = intervalHours > 0
    ? Date.now() + intervalHours * 3600 * 1000
    : null;

  const schedule: ScanSchedule = {
    frequency,
    enabled: true,
    preferredHour,
    lastScanTimestamp: null,
    nextScanTimestamp: nextTimestamp,
    notificationId,
    dailyDigestEnabled: false,
    dailyDigestHour: preferredHour,
  };

  await saveSchedule(schedule);
  return schedule;
}

export async function disableSchedule(): Promise<ScanSchedule> {
  await cancelScheduledScanReminders();
  const schedule: ScanSchedule = { ...defaultSchedule, enabled: false };
  await saveSchedule(schedule);
  return schedule;
}

export async function updateLastScan(): Promise<void> {
  const schedule = await getSchedule();
  const intervalHours = frequencyToHours(schedule.frequency);

  schedule.lastScanTimestamp = Date.now();
  schedule.nextScanTimestamp = intervalHours > 0
    ? Date.now() + intervalHours * 3600 * 1000
    : null;

  await saveSchedule(schedule);
}

export async function toggleDailyDigest(
  enabled: boolean,
  hour: number = 9
): Promise<void> {
  const schedule = await getSchedule();
  schedule.dailyDigestEnabled = enabled;
  schedule.dailyDigestHour = hour;
  await saveSchedule(schedule);

  if (enabled) {
    await scheduleDailyDigest(hour);
  }
}

function frequencyToHours(frequency: ScheduleFrequency): number {
  switch (frequency) {
    case 'daily': return 24;
    case 'weekly': return 168;
    case 'biweekly': return 336;
    case 'monthly': return 720;
    case 'manual':
    default: return 0;
  }
}

export function getNextScanLabel(schedule: ScanSchedule): string {
  if (!schedule.enabled || !schedule.nextScanTimestamp) return 'Not scheduled';

  const diff = schedule.nextScanTimestamp - Date.now();
  if (diff <= 0) return 'Overdue';

  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(hours / 24);

  if (days > 0) return `In ${days} day${days > 1 ? 's' : ''}`;
  if (hours > 0) return `In ${hours} hour${hours > 1 ? 's' : ''}`;
  return 'Soon';
}

// ─── Scan History Persistence ───────────────────────────────────

export async function getScanHistory(): Promise<ScanHistoryEntry[]> {
  try {
    const stored = await AsyncStorage.getItem(HISTORY_KEY);
    if (stored) return JSON.parse(stored);
  } catch (err) {
    console.warn('[Scheduler] Failed to read history:', err);
  }
  return [];
}

export async function addScanToHistory(entry: ScanHistoryEntry): Promise<void> {
  try {
    const history = await getScanHistory();
    history.unshift(entry); // Most recent first
    // Keep last 50 scans
    const trimmed = history.slice(0, 50);
    await AsyncStorage.setItem(HISTORY_KEY, JSON.stringify(trimmed));
  } catch (err) {
    console.warn('[Scheduler] Failed to save history:', err);
  }
}

export async function clearScanHistory(): Promise<void> {
  try {
    await AsyncStorage.removeItem(HISTORY_KEY);
  } catch (err) {
    console.warn('[Scheduler] Failed to clear history:', err);
  }
}

export async function getHistoryStats(): Promise<{
  totalScans: number;
  avgRiskScore: number;
  lastScanDate: string | null;
  highestRisk: number;
  lowestRisk: number;
  criticalThreatCount: number;
}> {
  const history = await getScanHistory();

  if (history.length === 0) {
    return {
      totalScans: 0,
      avgRiskScore: 0,
      lastScanDate: null,
      highestRisk: 0,
      lowestRisk: 0,
      criticalThreatCount: 0,
    };
  }

  const scores = history.map((h) => h.riskScore);
  return {
    totalScans: history.length,
    avgRiskScore: Math.round(scores.reduce((a, b) => a + b, 0) / scores.length),
    lastScanDate: new Date(history[0].timestamp).toLocaleDateString(),
    highestRisk: Math.max(...scores),
    lowestRisk: Math.min(...scores),
    criticalThreatCount: history.reduce((sum, h) => sum + h.criticalCount, 0),
  };
}
