import type { ThreatFamily } from '../types/engine';

/**
 * Threat Signature Database
 * In production, this would be loaded from a local SQLite DB
 * and updated periodically via secure delta downloads.
 */
export const threatFamilies: ThreatFamily[] = [
  {
    id: 'zeroday-rat',
    name: 'ZeroDayRAT',
    aliases: ['ZDR', 'NullAccess'],
    severity: 'critical',
    category: 'Remote Access Trojan',
    description:
      'Sophisticated RAT exploiting zero-day vulnerabilities for persistent Android access. Capable of keylogging, screen capture, and credential harvesting.',
    indicators: [
      'SHA256: e7a3b2...f4c1',
      'Package pattern: com.sysupdate.*',
      'C2: update-checker[.]net',
      'Battery drain anomaly >20%',
    ],
    detectionCount: 142,
    firstSeen: '2024-01-15',
    lastSeen: '2025-01-10',
    packagePatterns: ['com\\.sysupdate\\..*', 'com\\.system\\.updateservice'],
    hashSignatures: ['e7a3b2c4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f4c1'],
    c2Domains: ['update-checker.net', 'sys-update-service.com'],
  },
  {
    id: 'anubis',
    name: 'Anubis',
    aliases: ['Android.Anubis', 'BankBot.Anubis'],
    severity: 'critical',
    category: 'Banking Trojan',
    description:
      'One of the most prevalent Android banking trojans. Uses overlay attacks to steal credentials, supports SMS interception for 2FA bypass.',
    indicators: [
      'SHA256: a3f7c9...9e2c',
      'Requests: overlay, sms, contacts',
      'C2: anubis-panel[.]xyz',
      'Behavior: Accessibility abuse',
    ],
    detectionCount: 892,
    firstSeen: '2022-03-20',
    lastSeen: '2025-01-12',
    packagePatterns: ['com\\.anubis\\..*', 'com\\.bankhelper\\..*'],
    hashSignatures: ['a3f7c9e2d4b5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f89e2c'],
    c2Domains: ['anubis-panel.xyz', 'anubis-c2.top'],
  },
  {
    id: 'ahmyth',
    name: 'AhMyth',
    aliases: ['AhMyth RAT', 'AMRat'],
    severity: 'high',
    category: 'Open-Source RAT',
    description:
      'Open-source Android RAT widely used by threat actors. Provides full device control including camera, microphone, and file access.',
    indicators: [
      'SHA256: b8d4e1...7a3f',
      'Default port: 4444',
      'Package: ahmy.serv',
      'Permissions: camera, mic, storage',
    ],
    detectionCount: 356,
    firstSeen: '2023-06-10',
    lastSeen: '2025-01-08',
    packagePatterns: ['ahmyth\\..*', 'com\\.ahmyth\\..*'],
    hashSignatures: ['b8d4e1f2a3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c7a3f'],
    c2Domains: [],
  },
  {
    id: 'sparkcat',
    name: 'SparkCat',
    aliases: ['SparkCat Stealer'],
    severity: 'critical',
    category: 'Credential Stealer',
    description:
      'Advanced credential stealer targeting cryptocurrency wallet recovery phrases. Uses OCR to scan screenshots and photos for mnemonic phrases.',
    indicators: [
      'SHA256: c9e5f2...b4d8',
      'Screenshot frequency anomaly',
      'OCR library: tess-two',
      'C2: spark-sync[.]com',
    ],
    detectionCount: 234,
    firstSeen: '2024-05-22',
    lastSeen: '2025-01-11',
    packagePatterns: ['com\\.spark\\..*', 'com\\.photoutil\\..*'],
    hashSignatures: ['c9e5f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8b4d8'],
    c2Domains: ['spark-sync.com', 'spark-cdn.net'],
  },
  {
    id: 'anatsa',
    name: 'Anatsa',
    aliases: ['Android.Anatsa', 'TeaBot variant'],
    severity: 'critical',
    category: 'Banking Trojan',
    description:
      'Dropper-style banking trojan distributed through fake app stores. Drops multiple payloads for persistence and credential theft.',
    indicators: [
      'SHA256: d2a8c3...f5e9',
      'Droppers: fake PDF readers',
      'C2: anatsa-cdn[.]net',
      'Payload count: 3+ stages',
    ],
    detectionCount: 567,
    firstSeen: '2023-11-05',
    lastSeen: '2025-01-12',
    packagePatterns: ['com\\.pdf\\.reader\\.free.*', 'com\\.docreader\\..*'],
    hashSignatures: ['d2a8c3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9f5e9'],
    c2Domains: ['anatsa-cdn.net', 'anatsa-panel.com'],
  },
  {
    id: 'cocospy',
    name: 'Cocospy',
    aliases: ['SpyTracker', 'PhoneMonitor'],
    severity: 'high',
    category: 'Stalkerware',
    description:
      'Commercial stalkerware operating in stealth mode, exfiltrating location, messages, call logs, and browsing history.',
    indicators: [
      'SHA256: e5b9d4...c6a0',
      'Hidden icon',
      'Device admin abuse',
      'Exfil: cocospy-api[.]com',
    ],
    detectionCount: 189,
    firstSeen: '2023-02-14',
    lastSeen: '2025-01-09',
    packagePatterns: ['com\\.cocospy\\..*', 'com\\.monitor\\.system.*'],
    hashSignatures: ['e5b9d4a3c2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8c6a0'],
    c2Domains: ['cocospy-api.com', 'cocospy-data.net'],
  },
  {
    id: 'paragon-graphite',
    name: 'Paragon Graphite',
    aliases: ['Graphite', 'Paragon.A'],
    severity: 'high',
    category: 'Commercial Spyware',
    description:
      'Sophisticated commercial spyware sold to nation-state actors. Exploits zero-click vulnerabilities with self-destruct capability.',
    indicators: [
      'SHA256: f7c2e8...d3b1',
      'Zero-click delivery',
      'iMessage/WhatsApp exploits',
      'Self-destruct timer',
    ],
    detectionCount: 67,
    firstSeen: '2024-08-30',
    lastSeen: '2025-01-06',
    packagePatterns: [],
    hashSignatures: ['f7c2e8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5d3b1'],
    c2Domains: [],
  },
  {
    id: 'darksword',
    name: 'DarkSword',
    aliases: ['DSLoader', 'NightBlade'],
    severity: 'critical',
    category: 'Loader / Downloader',
    description:
      'Modular malware loader that fetches payloads from encrypted C2 channels. Uses domain generation algorithm (DGA) for resilient infrastructure.',
    indicators: [
      'SHA256: a1d6f3...e8c5',
      'DGA pattern: 16-char domains',
      'Encrypted C2: TLS 1.3 + custom',
      'Module loader: reflective',
    ],
    detectionCount: 445,
    firstSeen: '2024-02-18',
    lastSeen: '2025-01-12',
    packagePatterns: ['com\\.loader\\..*', 'com\\.nightservice\\..*'],
    hashSignatures: ['a1d6f3e4c5b6a7d8e9f0c1b2a3d4e5f6c7b8a9d0e1f2c3b4a5d6e7f8c9e8c5'],
    c2Domains: [],
  },
];

/**
 * Known dangerous permission combinations that indicate spyware
 */
export const dangerousPermCombos: { permissions: string[]; risk: string; severity: string }[] = [
  {
    permissions: ['android.permission.READ_SMS', 'android.permission.INTERNET'],
    risk: 'SMS exfiltration — app can read and transmit SMS messages',
    severity: 'critical',
  },
  {
    permissions: ['android.permission.CAMERA', 'android.permission.RECORD_AUDIO', 'android.permission.INTERNET'],
    risk: 'Surveillance — app can capture audio/video and transmit',
    severity: 'critical',
  },
  {
    permissions: ['android.permission.READ_CONTACTS', 'android.permission.READ_SMS', 'android.permission.INTERNET'],
    risk: 'Data harvesting — app can read contacts, SMS and exfiltrate',
    severity: 'high',
  },
  {
    permissions: ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.INTERNET', 'android.permission.RECEIVE_BOOT_COMPLETED'],
    risk: 'Location tracking — app tracks GPS and starts on boot',
    severity: 'high',
  },
  {
    permissions: ['android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.BIND_ACCESSIBILITY_SERVICE'],
    risk: 'Overlay + Accessibility abuse — common banking trojan pattern',
    severity: 'critical',
  },
  {
    permissions: ['android.permission.READ_CALL_LOG', 'android.permission.RECORD_AUDIO', 'android.permission.INTERNET'],
    risk: 'Call interception — app can monitor and record calls',
    severity: 'critical',
  },
  {
    permissions: ['android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.INTERNET'],
    risk: 'Dropper capability — app can download and install additional APKs',
    severity: 'high',
  },
];

/**
 * Known malicious C2 domains for network check
 */
export const knownC2Domains: string[] = [
  'update-checker.net',
  'anubis-panel.xyz',
  'spark-sync.com',
  'anatsa-cdn.net',
  'cocospy-api.com',
  'sys-update-service.com',
  'anubis-c2.top',
  'spark-cdn.net',
  'anatsa-panel.com',
  'cocospy-data.net',
  // Add more from public threat intel feeds
];

// ─── Utility functions ────────────────────────────────────────
export const getThreatById = (id: string) =>
  threatFamilies.find((t) => t.id === id);

export const getThreatsBySeverity = (severity: ThreatFamily['severity']) =>
  threatFamilies.filter((t) => t.severity === severity);

export const getThreatStats = () => ({
  total: threatFamilies.length,
  critical: threatFamilies.filter((t) => t.severity === 'critical').length,
  high: threatFamilies.filter((t) => t.severity === 'high').length,
  medium: threatFamilies.filter((t) => t.severity === 'medium').length,
  low: threatFamilies.filter((t) => t.severity === 'low').length,
});
