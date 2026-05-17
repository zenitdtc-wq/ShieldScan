/**
 * ShieldScan Native Bridge
 *
 * Interface between React Native JS and native Android scanning APIs.
 * On Android, this will call actual system APIs through native modules.
 * Provides fallback mock data when running on unsupported platforms.
 */

import { Platform, NativeModules } from 'react-native';
import type {
  InstalledApp,
  RunningServiceInfo,
  NetworkConnection,
  SystemIntegrityInfo,
} from '../types/engine';

// Native module reference (will be implemented in Java/Kotlin)
const { ShieldScanModule } = NativeModules;

const isAndroid = Platform.OS === 'android';

/**
 * Get all installed applications with their permissions
 */
export async function getInstalledApps(): Promise<InstalledApp[]> {
  if (isAndroid && ShieldScanModule?.getInstalledApps) {
    try {
      const result = await ShieldScanModule.getInstalledApps();
      return JSON.parse(result);
    } catch (err) {
      console.warn('[NativeBridge] getInstalledApps failed, using fallback:', err);
    }
  }
  return getMockInstalledApps();
}

/**
 * Get running services on the device
 */
export async function getRunningServices(): Promise<RunningServiceInfo[]> {
  if (isAndroid && ShieldScanModule?.getRunningServices) {
    try {
      const result = await ShieldScanModule.getRunningServices();
      return JSON.parse(result);
    } catch (err) {
      console.warn('[NativeBridge] getRunningServices failed, using fallback:', err);
    }
  }
  return getMockRunningServices();
}

/**
 * Get active network connections
 */
export async function getNetworkConnections(): Promise<NetworkConnection[]> {
  if (isAndroid && ShieldScanModule?.getNetworkConnections) {
    try {
      const result = await ShieldScanModule.getNetworkConnections();
      return JSON.parse(result);
    } catch (err) {
      console.warn('[NativeBridge] getNetworkConnections failed, using fallback:', err);
    }
  }
  return getMockNetworkConnections();
}

/**
 * Get system integrity information
 */
export async function getSystemIntegrity(): Promise<SystemIntegrityInfo> {
  if (isAndroid && ShieldScanModule?.getSystemIntegrity) {
    try {
      const result = await ShieldScanModule.getSystemIntegrity();
      return JSON.parse(result);
    } catch (err) {
      console.warn('[NativeBridge] getSystemIntegrity failed, using fallback:', err);
    }
  }
  return getMockSystemIntegrity();
}

/**
 * Compute SHA256 hash of a file (APK)
 */
export async function computeFileHash(filePath: string): Promise<string> {
  if (isAndroid && ShieldScanModule?.computeFileHash) {
    try {
      return await ShieldScanModule.computeFileHash(filePath);
    } catch (err) {
      console.warn('[NativeBridge] computeFileHash failed:', err);
    }
  }
  return 'mock-hash-' + filePath.split('/').pop();
}

/**
 * Request uninstall of an app (opens system dialog)
 */
export async function requestUninstall(packageName: string): Promise<boolean> {
  if (isAndroid && ShieldScanModule?.requestUninstall) {
    try {
      return await ShieldScanModule.requestUninstall(packageName);
    } catch (err) {
      console.warn('[NativeBridge] requestUninstall failed:', err);
    }
  }
  console.log('[NativeBridge] Mock uninstall:', packageName);
  return true;
}

/**
 * Open app settings for a specific package
 */
export async function openAppSettings(packageName: string): Promise<void> {
  if (isAndroid && ShieldScanModule?.openAppSettings) {
    try {
      await ShieldScanModule.openAppSettings(packageName);
      return;
    } catch (err) {
      console.warn('[NativeBridge] openAppSettings failed:', err);
    }
  }
  console.log('[NativeBridge] Mock open settings for:', packageName);
}

/**
 * Check if device has active VPN connection
 */
export async function hasActiveVPN(): Promise<boolean> {
  if (isAndroid && ShieldScanModule?.hasActiveVPN) {
    try {
      return await ShieldScanModule.hasActiveVPN();
    } catch (err) {
      console.warn('[NativeBridge] hasActiveVPN failed:', err);
    }
  }
  return false;
}

// ─── Mock Data (used when native module not available) ──────────

/**
 * Toggle Ghost Mode (Camouflage)
 */
export async function toggleGhostMode(enabled: boolean): Promise<boolean> {
  if (isAndroid && ShieldScanModule?.toggleGhostMode) {
    try {
      return await ShieldScanModule.toggleGhostMode(enabled);
    } catch (err) {
      console.warn('[NativeBridge] toggleGhostMode failed:', err);
    }
  }
  return false;
}

/**
 * Toggle Local VPN Network Monitor
 */
export async function toggleVpnMonitor(enabled: boolean): Promise<boolean> {
  if (isAndroid && ShieldScanModule?.toggleVpnMonitor) {
    try {
      return await ShieldScanModule.toggleVpnMonitor(enabled);
    } catch (err) {
      console.warn('[NativeBridge] toggleVpnMonitor failed:', err);
    }
  }
  return false;
}

function getMockInstalledApps(): InstalledApp[] {
  return [
    {
      packageName: 'com.example.flashlightpro',
      appName: 'Flashlight Pro',
      versionName: '2.1.0',
      versionCode: 21,
      isSystemApp: false,
      installTime: Date.now() - 86400000 * 30,
      lastUpdateTime: Date.now() - 86400000 * 5,
      permissions: [
        { name: 'android.permission.READ_SMS', granted: true, riskLevel: 'critical', description: 'Read SMS messages' },
        { name: 'android.permission.INTERNET', granted: true, riskLevel: 'low', description: 'Full network access' },
        { name: 'android.permission.READ_CONTACTS', granted: true, riskLevel: 'high', description: 'Read contacts' },
        { name: 'android.permission.CAMERA', granted: true, riskLevel: 'medium', description: 'Take photos and videos' },
      ],
      apkPath: '/data/app/com.example.flashlightpro/base.apk',
      apkSize: 15728640,
    },
    {
      packageName: 'com.example.batterysaver',
      appName: 'Battery Saver Pro',
      versionName: '1.3.2',
      versionCode: 13,
      isSystemApp: false,
      installTime: Date.now() - 86400000 * 60,
      lastUpdateTime: Date.now() - 86400000 * 10,
      permissions: [
        { name: 'android.permission.RECEIVE_BOOT_COMPLETED', granted: true, riskLevel: 'medium', description: 'Run at startup' },
        { name: 'android.permission.INTERNET', granted: true, riskLevel: 'low', description: 'Full network access' },
        { name: 'android.permission.ACCESS_FINE_LOCATION', granted: true, riskLevel: 'high', description: 'Access precise location' },
        { name: 'android.permission.WAKE_LOCK', granted: true, riskLevel: 'low', description: 'Prevent phone from sleeping' },
      ],
      apkPath: '/data/app/com.example.batterysaver/base.apk',
      apkSize: 8388608,
    },
    {
      packageName: 'com.example.calendarwidget',
      appName: 'Calendar Widget',
      versionName: '3.0.1',
      versionCode: 30,
      isSystemApp: false,
      installTime: Date.now() - 86400000 * 90,
      lastUpdateTime: Date.now() - 86400000 * 2,
      permissions: [
        { name: 'android.permission.INTERNET', granted: true, riskLevel: 'low', description: 'Full network access' },
        { name: 'android.permission.READ_CALENDAR', granted: true, riskLevel: 'medium', description: 'Read calendar events' },
      ],
      apkPath: '/data/app/com.example.calendarwidget/base.apk',
      apkSize: 5242880,
    },
    {
      packageName: 'com.example.notesapp',
      appName: 'Quick Notes',
      versionName: '1.0.0',
      versionCode: 1,
      isSystemApp: false,
      installTime: Date.now() - 86400000 * 15,
      lastUpdateTime: Date.now() - 86400000 * 15,
      permissions: [
        { name: 'android.permission.WRITE_EXTERNAL_STORAGE', granted: true, riskLevel: 'medium', description: 'Modify storage' },
      ],
      apkPath: '/data/app/com.example.notesapp/base.apk',
      apkSize: 3145728,
    },
    {
      packageName: 'com.android.chrome',
      appName: 'Chrome',
      versionName: '120.0.6099.43',
      versionCode: 609904300,
      isSystemApp: true,
      installTime: Date.now() - 86400000 * 365,
      lastUpdateTime: Date.now() - 86400000 * 3,
      permissions: [
        { name: 'android.permission.INTERNET', granted: true, riskLevel: 'safe', description: 'Full network access' },
        { name: 'android.permission.CAMERA', granted: true, riskLevel: 'safe', description: 'Camera access' },
      ],
      apkPath: '/data/app/com.android.chrome/base.apk',
      apkSize: 209715200,
    },
  ];
}

function getMockRunningServices(): RunningServiceInfo[] {
  return [
    {
      packageName: 'com.example.batterysaver',
      serviceName: 'com.example.batterysaver.BackgroundMonitor',
      pid: 12345,
      isForeground: false,
      memoryUsageKb: 45000,
      startTime: Date.now() - 3600000,
    },
    {
      packageName: 'com.example.calendarwidget',
      serviceName: 'com.example.calendarwidget.SyncService',
      pid: 12346,
      isForeground: false,
      memoryUsageKb: 12000,
      startTime: Date.now() - 7200000,
    },
    {
      packageName: 'com.android.systemui',
      serviceName: 'com.android.systemui.SystemUIService',
      pid: 1001,
      isForeground: true,
      memoryUsageKb: 85000,
    },
  ];
}

function getMockNetworkConnections(): NetworkConnection[] {
  return [
    {
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 45234,
      remoteAddress: '185.220.101.42',
      remotePort: 443,
      state: 'ESTABLISHED',
      packageName: 'com.example.calendarwidget',
    },
    {
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 38901,
      remoteAddress: '142.250.80.46',
      remotePort: 443,
      state: 'ESTABLISHED',
      packageName: 'com.android.chrome',
    },
    {
      protocol: 'UDP',
      localAddress: '192.168.1.100',
      localPort: 5353,
      remoteAddress: '224.0.0.251',
      remotePort: 5353,
      state: 'LISTEN',
    },
    {
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 52100,
      remoteAddress: '104.18.32.7',
      remotePort: 80,
      state: 'ESTABLISHED',
      packageName: 'com.example.flashlightpro',
    },
  ];
}

function getMockSystemIntegrity(): SystemIntegrityInfo {
  return {
    isRooted: false,
    isBootloaderUnlocked: false,
    isDeveloperModeEnabled: true,
    isUsbDebuggingEnabled: true,
    isAdbOverWifi: false,
    isEncrypted: true,
    securityPatchDate: '2025-01-05',
    androidVersion: '14',
    buildFingerprint: 'google/raven/raven:14/AP2A.240305.019/11445699:user/release-keys',
    seLinuxStatus: 'enforcing',
  };
}
