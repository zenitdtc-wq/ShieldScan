/**
 * ShieldScan Push Notifications
 *
 * Handles local notifications for:
 * - Scan completion results
 * - Scheduled scan reminders
 * - Critical threat alerts
 * - Remediation progress updates
 */

import * as Notifications from 'expo-notifications';
import * as Device from 'expo-device';
import { Platform } from 'react-native';
import type { RiskScore, ScanResult } from '../types/engine';

// ─── Configure notification behavior ───────────────────────────
Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
    shouldShowBanner: true,
    shouldShowList: true,
  }),
});

// ─── Permission Request ────────────────────────────────────────
export async function requestNotificationPermissions(): Promise<boolean> {
  if (!Device.isDevice) {
    console.log('[Notifications] Must use physical device');
    return false;
  }

  const { status: existingStatus } = await Notifications.getPermissionsAsync();
  let finalStatus = existingStatus;

  if (existingStatus !== 'granted') {
    const { status } = await Notifications.requestPermissionsAsync();
    finalStatus = status;
  }

  if (finalStatus !== 'granted') {
    console.log('[Notifications] Permission not granted');
    return false;
  }

  // Android channel setup
  if (Platform.OS === 'android') {
    await Notifications.setNotificationChannelAsync('scan-results', {
      name: 'Scan Results',
      importance: Notifications.AndroidImportance.HIGH,
      vibrationPattern: [0, 250, 250, 250],
      lightColor: '#00F5D4',
      sound: 'default',
    });

    await Notifications.setNotificationChannelAsync('threat-alerts', {
      name: 'Threat Alerts',
      importance: Notifications.AndroidImportance.MAX,
      vibrationPattern: [0, 500, 250, 500],
      lightColor: '#FF3B5C',
      sound: 'default',
    });

    await Notifications.setNotificationChannelAsync('scheduled-scans', {
      name: 'Scheduled Scans',
      importance: Notifications.AndroidImportance.DEFAULT,
      sound: 'default',
    });

    await Notifications.setNotificationChannelAsync('remediation', {
      name: 'Remediation Updates',
      importance: Notifications.AndroidImportance.DEFAULT,
      sound: 'default',
    });
  }

  return true;
}

// ─── Scan Complete Notification ─────────────────────────────────
export async function notifyScanComplete(
  riskScore: RiskScore,
  results: ScanResult[]
): Promise<void> {
  const criticalCount = results.filter((r) => r.severity === 'critical').length;
  const highCount = results.filter((r) => r.severity === 'high').length;
  const totalFindings = results.length;

  let title: string;
  let body: string;
  let channelId = 'scan-results';

  if (criticalCount > 0) {
    title = `⚠️ ${criticalCount} Critical Threat${criticalCount > 1 ? 's' : ''} Detected!`;
    body = `Risk score: ${riskScore.overall}/100. ${totalFindings} total findings require immediate attention.`;
    channelId = 'threat-alerts';
  } else if (highCount > 0) {
    title = `🔶 ${highCount} High-Risk Issue${highCount > 1 ? 's' : ''} Found`;
    body = `Risk score: ${riskScore.overall}/100. Review ${totalFindings} findings in ShieldScan.`;
  } else if (totalFindings > 0) {
    title = '🔵 Scan Complete — Minor Issues Found';
    body = `Risk score: ${riskScore.overall}/100. ${totalFindings} low-priority findings detected.`;
  } else {
    title = '✅ Scan Complete — All Clear!';
    body = `Risk score: ${riskScore.overall}/100. No threats detected. Your device is secure.`;
  }

  await Notifications.scheduleNotificationAsync({
    content: {
      title,
      body,
      data: { type: 'scan_complete', riskScore: riskScore.overall },
      sound: 'default',
      ...(Platform.OS === 'android' && { channelId }),
    },
    trigger: null, // Immediate
  });
}

// ─── Critical Threat Alert ──────────────────────────────────────
export async function notifyCriticalThreat(result: ScanResult): Promise<void> {
  await Notifications.scheduleNotificationAsync({
    content: {
      title: '🚨 Critical Threat Detected',
      body: `${result.title}: ${result.description.slice(0, 100)}...`,
      data: { type: 'critical_threat', resultId: result.id },
      sound: 'default',
      ...(Platform.OS === 'android' && { channelId: 'threat-alerts' }),
    },
    trigger: null,
  });
}

// ─── Scheduled Scan Reminder ────────────────────────────────────
export async function scheduleNextScanReminder(
  intervalHours: number
): Promise<string> {
  // Cancel existing scheduled scan notifications
  await cancelScheduledScanReminders();

  const id = await Notifications.scheduleNotificationAsync({
    content: {
      title: '🛡️ Time for a Security Scan',
      body: 'Your scheduled security scan is due. Tap to run ShieldScan now.',
      data: { type: 'scheduled_scan' },
      sound: 'default',
      ...(Platform.OS === 'android' && { channelId: 'scheduled-scans' }),
    },
    trigger: {
      type: Notifications.SchedulableTriggerInputTypes.TIME_INTERVAL,
      seconds: intervalHours * 3600,
      repeats: true,
    },
  });

  return id;
}

// ─── Cancel Scheduled Reminders ─────────────────────────────────
export async function cancelScheduledScanReminders(): Promise<void> {
  const scheduled = await Notifications.getAllScheduledNotificationsAsync();
  for (const notif of scheduled) {
    if (notif.content.data?.type === 'scheduled_scan') {
      await Notifications.cancelScheduledNotificationAsync(notif.identifier);
    }
  }
}

// ─── Remediation Progress ───────────────────────────────────────
export async function notifyRemediationComplete(
  threatsRemoved: number
): Promise<void> {
  await Notifications.scheduleNotificationAsync({
    content: {
      title: '✅ Remediation Complete',
      body: `Successfully processed ${threatsRemoved} threat${threatsRemoved > 1 ? 's' : ''}. Run a verification scan to confirm.`,
      data: { type: 'remediation_complete' },
      sound: 'default',
      ...(Platform.OS === 'android' && { channelId: 'remediation' }),
    },
    trigger: null,
  });
}

// ─── Daily Digest ───────────────────────────────────────────────
export async function scheduleDailyDigest(hour: number = 9): Promise<string> {
  const id = await Notifications.scheduleNotificationAsync({
    content: {
      title: '📊 Daily Security Digest',
      body: 'Tap to view your device security status and any new threats.',
      data: { type: 'daily_digest' },
      sound: 'default',
      ...(Platform.OS === 'android' && { channelId: 'scheduled-scans' }),
    },
    trigger: {
      type: Notifications.SchedulableTriggerInputTypes.DAILY,
      hour,
      minute: 0,
    },
  });
  return id;
}

// ─── Get Pending Notifications Count ────────────────────────────
export async function getPendingNotificationCount(): Promise<number> {
  const scheduled = await Notifications.getAllScheduledNotificationsAsync();
  return scheduled.length;
}

// ─── Notification Response Listener ─────────────────────────────
export function addNotificationResponseListener(
  callback: (data: Record<string, unknown>) => void
): Notifications.EventSubscription {
  return Notifications.addNotificationResponseReceivedListener((response) => {
    const data = response.notification.request.content.data;
    callback(data as Record<string, unknown>);
  });
}
