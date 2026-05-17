/**
 * ShieldScan — Deep File & Cache Scanner
 *
 * Scans device files for threats with multi-layer detection:
 *   - Magic byte analysis (APK/DEX/ELF/shell detection)
 *   - Shannon entropy measurement (encrypted payload detection)
 *   - Embedded string extraction (C2 URLs, exploit patterns)
 *   - Signature database matching (known malware indicators)
 *   - Path-based heuristics (staging directories, hidden files)
 *   - Browser download & cache scanning
 *   - Multi-indicator confidence scoring
 *
 * Works independently of AI — pure deterministic analysis.
 */

import * as FileSystem from 'expo-file-system/legacy';
import AsyncStorage from '@react-native-async-storage/async-storage';
import type { ScanResult } from '../types/engine';
import {
  fileMagicSignatures,
  suspiciousFileStrings,
  maliciousFilePathPatterns,
  ENTROPY_THRESHOLDS,
} from '../data/signatures';

// ─── Types ─────────────────────────────────────────────────────

export interface FileScanTarget {
  id: string;
  name: string;
  path: string;
  icon: string;
  description: string;
}

export interface FileScanProgress {
  currentFolder: string;
  filesScanned: number;
  threatsFound: number;
  progress: number;
  currentFile?: string;
  deepAnalysisActive?: boolean;
}

export interface FileAnalysisResult {
  indicators: string[];
  confidence: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
}

// ─── Deep Analysis Config ─────────────────────────────────────

const DEEP_SCAN_SIZE_LIMIT = 10 * 1024 * 1024; // Only deep-scan files < 10MB
const READ_CHUNK_SIZE = 4096; // Read first 4KB for header/string analysis
const MAX_DEEP_SCAN_PER_DIR = 50; // Deep scan cap per directory

// ─── Default Scan Targets ──────────────────────────────────────

export const DEFAULT_SCAN_TARGETS: FileScanTarget[] = [
  {
    id: 'downloads',
    name: 'Downloads',
    path: `${FileSystem.documentDirectory}../Download`,
    icon: 'download',
    description: 'Downloaded files from browsers and apps',
  },
  {
    id: 'cache',
    name: 'App Cache',
    path: `${FileSystem.cacheDirectory}`,
    icon: 'file-tray-stacked',
    description: 'Temporary files stored by apps',
  },
  {
    id: 'documents',
    name: 'Documents',
    path: `${FileSystem.documentDirectory}`,
    icon: 'document',
    description: 'App document storage',
  },
];

const CUSTOM_FOLDERS_KEY = '@shieldscan_custom_scan_folders';

// ─── Threat Patterns ───────────────────────────────────────────

const SUSPICIOUS_EXTENSIONS = new Set([
  '.apk', '.xapk', '.dex', '.jar', '.sh', '.bat', '.cmd',
  '.exe', '.scr', '.pif', '.vbs', '.js', '.wsf',
  '.so', '.bin', '.dat', '.enc', '.tmp', '.bak',
  '.class', '.war',  // Java class/archive files
]);

// Java-specific threat extensions — should NEVER appear on Android
const JAVA_THREAT_EXTENSIONS = new Set([
  '.class', '.jar', '.war', '.jnlp',
]);

// Extensions that should NEVER appear in cache/downloads (strong signal)
const CRITICAL_EXTENSIONS = new Set([
  '.dex', '.so', '.sh', '.apk',
]);

const SUSPICIOUS_FILENAMES = [
  /^\./, // Hidden files (dot-prefix)
  /payload/i,
  /exploit/i,
  /rat\b/i,
  /trojan/i,
  /keylog/i,
  /inject/i,
  /hook/i,
  /rootkit/i,
  /backdoor/i,
  /spyware/i,
  /meterpreter/i,
  /xmrig/i,
  /cryptonight/i,
  /minerd/i,
  /shell\.(apk|dex|jar)/i,
  /update_flash/i,
  /video_codec/i,
  /install_to_watch/i,
  /dropper/i,
  /loader\.(dex|apk|bin)/i,
  /stage[0-9]/i, // Staged payloads: stage1, stage2, etc.
  /c2config/i,
  /\.nomedia$/, // Often used to hide folders from gallery
];

// Filenames that are DEFINITELY malware (100% confidence if found)
const KNOWN_MALWARE_FILENAMES = new Set([
  'b.dex', // Common SpyNote dropped payload
  'classes2.dex', // Outside APK = dropper
  'rat.apk',
  'payload.apk',
  'shell.dex',
  'update.apk', // In cache = almost certainly malware
  'base.apk.bak', // Backup of modified system app
  'payload.jar', // Java RAT payload
  'adwind.jar', // Adwind/jRAT
  'exploit.jar', // Generic Java exploit
  'log4shell.class', // Log4j exploit
  'cookies.db', // Stolen cookie database (outside browser dir)
  'login_data.db', // Stolen Chrome Login Data
  'sessions.json', // Stolen session tokens
  'stolen_cookies.txt', // Cookie exfiltration artifact
  'autofill.db', // Stolen autofill database
  'webcam_capture.jpg', // Sextortion camera capture
  'gallery_dump.zip', // Exfiltrated gallery
  'contacts_export.json', // Exfiltrated contacts for blackmail
]);

// Browser profile database filenames — should never appear OUTSIDE browser app data
const BROWSER_DB_FILENAMES = new Set([
  'cookies', 'cookies.db', 'cookies.sqlite',
  'login data', 'logins.json', 'signons.sqlite',
  'web data', 'key3.db', 'key4.db',
  'places.sqlite', 'formhistory.sqlite',
  'chrome_cookie', 'firefox_cookie',
]);

const LARGE_FILE_THRESHOLD = 100 * 1024 * 1024; // 100MB — suspicious for cache
const HIDDEN_APK_SIZE_MIN = 50 * 1024; // APKs under 50KB are suspicious stubs

// ─── Custom Folders ────────────────────────────────────────────

export async function getCustomFolders(): Promise<FileScanTarget[]> {
  try {
    const data = await AsyncStorage.getItem(CUSTOM_FOLDERS_KEY);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

export async function addCustomFolder(name: string, path: string): Promise<void> {
  const existing = await getCustomFolders();
  const newFolder: FileScanTarget = {
    id: `custom-${Date.now()}`,
    name,
    path,
    icon: 'folder-open',
    description: `Custom: ${path}`,
  };
  existing.push(newFolder);
  await AsyncStorage.setItem(CUSTOM_FOLDERS_KEY, JSON.stringify(existing));
}

export async function removeCustomFolder(id: string): Promise<void> {
  const existing = await getCustomFolders();
  const filtered = existing.filter((f) => f.id !== id);
  await AsyncStorage.setItem(CUSTOM_FOLDERS_KEY, JSON.stringify(filtered));
}

// ─── Browser-Specific Scan Paths ──────────────────────────────

const BROWSER_DOWNLOAD_PATHS = [
  '../Download/Chrome',
  '../Download/Firefox',
  '../Download/Brave',
  '../Download/Opera',
  '../Download/Samsung Internet',
  '../Download/Edge',
  '../Download/UC Browser',
];

// ─── Scanner ───────────────────────────────────────────────────

/**
 * Scan files in specified targets for threats.
 * Multi-layer detection: extension → filename → magic bytes → entropy → strings → path patterns.
 * Works completely offline — no AI needed.
 */
export async function scanFiles(
  targets?: FileScanTarget[],
  onProgress?: (progress: FileScanProgress) => void,
  deepScan: boolean = true,
): Promise<ScanResult[]> {
  const scanTargets = targets || DEFAULT_SCAN_TARGETS;
  const customFolders = await getCustomFolders();
  const browserTargets = await getBrowserDownloadTargets();
  const allTargets = [...scanTargets, ...browserTargets, ...customFolders];

  const findings: ScanResult[] = [];
  let totalScanned = 0;

  for (let i = 0; i < allTargets.length; i++) {
    const target = allTargets[i];

    onProgress?.({
      currentFolder: target.name,
      filesScanned: totalScanned,
      threatsFound: findings.length,
      progress: Math.round((i / allTargets.length) * 100),
      deepAnalysisActive: deepScan,
    });

    try {
      const dirInfo = await FileSystem.getInfoAsync(target.path);
      if (!dirInfo.exists || !dirInfo.isDirectory) continue;

      const targetFindings = await scanDirectory(target.path, target.id, 0, deepScan);
      findings.push(...targetFindings);
      totalScanned += targetFindings.length;
    } catch {
      // Directory not accessible — skip
    }
  }

  // Deduplicate findings by path (same file, multiple indicators → merge)
  const deduped = deduplicateFindings(findings);

  onProgress?.({
    currentFolder: 'Complete',
    filesScanned: totalScanned,
    threatsFound: deduped.length,
    progress: 100,
  });

  return deduped;
}

/**
 * Get browser-specific download directories that exist on this device.
 */
async function getBrowserDownloadTargets(): Promise<FileScanTarget[]> {
  const targets: FileScanTarget[] = [];
  const basePath = FileSystem.documentDirectory || '';

  for (const relPath of BROWSER_DOWNLOAD_PATHS) {
    const fullPath = `${basePath}${relPath}`;
    try {
      const info = await FileSystem.getInfoAsync(fullPath);
      if (info.exists && info.isDirectory) {
        const name = relPath.split('/').pop() || 'Browser';
        targets.push({
          id: `browser-${name.toLowerCase().replace(/\s/g, '-')}`,
          name: `${name} Downloads`,
          path: fullPath,
          icon: 'globe',
          description: `Files downloaded via ${name}`,
        });
      }
    } catch {
      // Not accessible
    }
  }

  return targets;
}

async function scanDirectory(
  path: string,
  sourceId: string,
  depth: number,
  deepScan: boolean,
): Promise<ScanResult[]> {
  if (depth > 4) return []; // Increased depth for thorough scan

  const findings: ScanResult[] = [];
  let deepScanned = 0;

  try {
    const entries = await FileSystem.readDirectoryAsync(path);

    // Check if this directory itself is suspicious (hidden dot-dir with executables)
    const dirName = path.split('/').pop() || '';
    if (dirName.startsWith('.') && depth > 0) {
      // Hidden directory — flag all executables inside as higher severity
      const execCount = entries.filter((e) => {
        const ext = e.toLowerCase().substring(e.lastIndexOf('.'));
        return CRITICAL_EXTENSIONS.has(ext);
      }).length;

      if (execCount > 0) {
        findings.push(createFinding({
          filename: dirName,
          fullPath: path,
          size: 0,
          sourceId,
          title: `Hidden directory with ${execCount} executable(s): ${dirName}`,
          description: `Hidden dot-directory contains ${execCount} executable file(s). This is a common malware staging technique to avoid detection.`,
          severity: 'critical',
          confidence: 85,
          evidence: [`Path: ${path}`, `Executables found: ${execCount}`, `Technique: Hidden staging directory`],
          recommendation: 'This hidden folder contains executables — a strong malware indicator. Delete the entire folder unless you created it.',
        }));
      }
    }

    for (const entry of entries.slice(0, 300)) { // Increased cap
      const fullPath = `${path}/${entry}`;

      try {
        const info = await FileSystem.getInfoAsync(fullPath);
        if (!info.exists) continue;

        if (info.isDirectory) {
          const subFindings = await scanDirectory(fullPath, sourceId, depth + 1, deepScan);
          findings.push(...subFindings);
        } else {
          const fileSize = (info as any).size || 0;

          // Layer 1: Quick pattern analysis (extension + filename)
          const quickResult = analyzeFileQuick(entry, fullPath, fileSize, sourceId);
          if (quickResult) findings.push(quickResult);

          // Layer 2: Deep binary analysis (magic bytes + entropy + strings)
          if (deepScan && fileSize > 0 && fileSize < DEEP_SCAN_SIZE_LIMIT && deepScanned < MAX_DEEP_SCAN_PER_DIR) {
            const shouldDeepScan = shouldPerformDeepScan(entry, fileSize, sourceId);
            if (shouldDeepScan) {
              deepScanned++;
              const deepResults = await analyzeFileDeep(entry, fullPath, fileSize, sourceId);
              findings.push(...deepResults);
            }
          }

          // Layer 3: Path-based heuristics
          const pathResult = analyzeFilePath(fullPath, entry, fileSize);
          if (pathResult) findings.push(pathResult);
        }
      } catch {
        // Can't access file — skip
      }
    }
  } catch {
    // Can't read directory
  }

  return findings;
}

/**
 * Decide if a file warrants deep scanning (reading bytes).
 * Avoids wasting time on obviously-safe files like images or media.
 */
function shouldPerformDeepScan(filename: string, size: number, sourceId: string): boolean {
  const lower = filename.toLowerCase();
  const ext = lower.substring(lower.lastIndexOf('.'));

  // Always deep-scan these
  if (CRITICAL_EXTENSIONS.has(ext)) return true;
  if (SUSPICIOUS_EXTENSIONS.has(ext)) return true;
  if (KNOWN_MALWARE_FILENAMES.has(lower)) return true;
  if (lower.startsWith('.')) return true; // Hidden files

  // Skip known safe media formats
  const safeExtensions = new Set([
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg',
    '.mp3', '.mp4', '.wav', '.ogg', '.m4a', '.m4v', '.avi',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.ttf', '.otf', '.woff', '.woff2',
  ]);
  if (safeExtensions.has(ext)) return false;

  // Deep-scan unknown extensions or no extension in suspicious locations
  if (sourceId === 'cache' && size > 100 * 1024) return true; // Large cache files
  if (!ext || ext === '.') return true; // No extension = suspicious

  return false;
}

// ─── Layer 1: Quick Pattern Analysis ──────────────────────────

function analyzeFileQuick(
  filename: string,
  fullPath: string,
  size: number,
  sourceId: string,
): ScanResult | null {
  const lower = filename.toLowerCase();
  const ext = lower.substring(lower.lastIndexOf('.'));

  // Known malware filenames — highest confidence
  if (KNOWN_MALWARE_FILENAMES.has(lower)) {
    return createFinding({
      filename, fullPath, size, sourceId,
      title: `Known malware file: ${filename}`,
      description: `File matches a known malware payload filename used by active threat families. This is almost certainly malicious.`,
      severity: 'critical',
      confidence: 95,
      evidence: [`Path: ${fullPath}`, `Size: ${formatSize(size)}`, `Match: Known malware filename database`],
      recommendation: 'Delete this file immediately. It matches a known malware payload name.',
    });
  }

  // Critical extensions in wrong places
  if (CRITICAL_EXTENSIONS.has(ext) && (sourceId === 'cache' || sourceId.startsWith('browser'))) {
    return createFinding({
      filename, fullPath, size, sourceId,
      title: `Executable in ${sourceId}: ${filename}`,
      description: `${ext.toUpperCase()} executable found in ${sourceId}. Executables should never appear in cache or browser downloads without explicit user action.`,
      severity: 'critical',
      confidence: 85,
      evidence: [`Path: ${fullPath}`, `Size: ${formatSize(size)}`, `Type: ${ext}`, `Location: ${sourceId}`],
      recommendation: 'This executable was placed in a location that suggests malware activity. Delete immediately.',
    });
  }

  // Suspicious extensions
  if (SUSPICIOUS_EXTENSIONS.has(ext)) {
    const severity = ext === '.apk' || ext === '.dex' || ext === '.so' ? 'high' : 'medium';
    return createFinding({
      filename, fullPath, size, sourceId,
      title: `Suspicious file: ${filename}`,
      description: `Found ${ext} file in ${sourceId}. This file type can contain executable code.`,
      severity,
      confidence: ext === '.apk' ? 70 : ext === '.dex' ? 80 : 55,
      evidence: [`Path: ${fullPath}`, `Size: ${formatSize(size)}`, `Type: ${ext}`],
      recommendation: ext === '.apk'
        ? 'Unknown APK files may contain malware. Delete unless you specifically downloaded this.'
        : 'This file type can execute malicious code. Delete if you did not create it.',
    });
  }

  // Suspicious filenames
  for (const pattern of SUSPICIOUS_FILENAMES) {
    if (pattern.test(filename)) {
      // .nomedia files are only low severity (used to hide folders)
      if (lower === '.nomedia') {
        return createFinding({
          filename, fullPath, size, sourceId,
          title: `Media hiding file: .nomedia`,
          description: `This file prevents the folder from appearing in gallery/media apps. Malware uses this to hide its data folder.`,
          severity: 'low',
          confidence: 30,
          evidence: [`Path: ${fullPath}`, `Technique: Gallery exclusion`],
          recommendation: 'This file hides a folder from media scanners. Check what else is in this folder.',
        });
      }
      return createFinding({
        filename, fullPath, size, sourceId,
        title: `Suspicious filename: ${filename}`,
        description: `File name matches known threat patterns (${pattern.source}).`,
        severity: 'medium',
        confidence: 55,
        evidence: [`Path: ${fullPath}`, `Size: ${formatSize(size)}`, `Pattern: ${pattern.source}`],
        recommendation: 'Investigate this file. Delete if you do not recognize it.',
      });
    }
  }

  // Abnormally large cache files
  if (sourceId === 'cache' && size > LARGE_FILE_THRESHOLD) {
    return createFinding({
      filename, fullPath, size, sourceId,
      title: `Large cache file: ${filename}`,
      description: `Unusually large file (${formatSize(size)}) in cache. May indicate data staging for exfiltration.`,
      severity: 'low',
      confidence: 35,
      evidence: [`Path: ${fullPath}`, `Size: ${formatSize(size)}`],
      recommendation: 'Large cache files are unusual. Clear app cache or delete this file.',
    });
  }

  // Tiny APK stubs (< 50KB APK = likely a loader/dropper stub)
  if (ext === '.apk' && size > 0 && size < HIDDEN_APK_SIZE_MIN) {
    return createFinding({
      filename, fullPath, size, sourceId,
      title: `Suspicious APK stub: ${filename}`,
      description: `Extremely small APK (${formatSize(size)}). Legitimate apps are larger. This may be a dropper stub that downloads the real payload.`,
      severity: 'high',
      confidence: 75,
      evidence: [`Path: ${fullPath}`, `Size: ${formatSize(size)}`, `Indicator: Sub-50KB APK`],
      recommendation: 'APK files this small are almost always dropper stubs. Delete immediately.',
    });
  }

  // ─── Java-specific threats ────────────────────────────────────
  // Java bytecode files should NEVER exist on Android outside of bundled APKs
  if (JAVA_THREAT_EXTENSIONS.has(ext)) {
    return createFinding({
      filename, fullPath, size, sourceId,
      title: `Java threat file: ${filename}`,
      description: `Java ${ext} file found on device. Android does not use standalone Java class files — this is a cross-platform RAT payload (jRAT/Adwind) or exploit artifact.`,
      severity: 'critical',
      confidence: 90,
      evidence: [
        `Path: ${fullPath}`,
        `Size: ${formatSize(size)}`,
        `Type: ${ext} (Java bytecode)`,
        `Context: Java files are never legitimate on Android outside APK bundles`,
      ],
      recommendation: 'Java class/JAR files on Android are always malicious. This is likely a RAT payload. Delete immediately.',
    });
  }

  // ─── Cookie/Session theft artifacts ───────────────────────────
  // Browser database files found OUTSIDE browser app directories = stolen
  if (BROWSER_DB_FILENAMES.has(lower) && !isBrowserDirectory(fullPath)) {
    return createFinding({
      filename, fullPath, size, sourceId,
      title: `Stolen browser data: ${filename}`,
      description: `Browser database file found outside its normal location. This is a strong indicator that browser cookies, passwords, or sessions have been copied for exfiltration.`,
      severity: 'critical',
      confidence: 92,
      evidence: [
        `Path: ${fullPath}`,
        `Size: ${formatSize(size)}`,
        `File: ${filename} (browser profile database)`,
        `Context: Found outside legitimate browser directory`,
      ],
      recommendation: 'This is a copied browser database — your cookies and saved passwords may be compromised. Delete this file and change your important passwords immediately.',
    });
  }

  // Token/session dump files
  if (/session|token|cookie/i.test(lower) && /\.(txt|json|db|sqlite|log)$/i.test(lower)) {
    if (!isBrowserDirectory(fullPath) && sourceId !== 'documents') {
      return createFinding({
        filename, fullPath, size, sourceId,
        title: `Session/cookie dump file: ${filename}`,
        description: `File with session/cookie/token naming found in suspicious location. May be exfiltrated authentication data.`,
        severity: 'high',
        confidence: 70,
        evidence: [`Path: ${fullPath}`, `Size: ${formatSize(size)}`, `Pattern: Session/token data filename`],
        recommendation: 'This may contain stolen login sessions. Delete and monitor your accounts for unauthorized access.',
      });
    }
  }

  return null;
}

/**
 * Check if a file path is inside a legitimate browser's data directory.
 */
function isBrowserDirectory(path: string): boolean {
  const browserPaths = [
    'com.android.chrome',
    'com.chrome.beta',
    'com.chrome.dev',
    'org.mozilla.firefox',
    'org.mozilla.fenix', // Firefox Nightly
    'com.brave.browser',
    'com.opera.browser',
    'com.opera.mini',
    'com.microsoft.emmx', // Edge
    'com.UCMobile', // UC Browser
    'com.sec.android.app.sbrowser', // Samsung Internet
    'com.duckduckgo.mobile.android',
  ];
  return browserPaths.some((bp) => path.includes(bp));
}

// ─── Layer 2: Deep Binary Analysis ────────────────────────────

/**
 * Read file header bytes and perform deep analysis:
 * - Magic byte matching against known file types
 * - Shannon entropy estimation for packed/encrypted detection
 * - String extraction for C2 URLs, exploit patterns
 */
async function analyzeFileDeep(
  filename: string,
  fullPath: string,
  size: number,
  sourceId: string,
): Promise<ScanResult[]> {
  const findings: ScanResult[] = [];

  try {
    // Read first chunk as base64 (expo-file-system only supports base64 reading)
    const readSize = Math.min(size, READ_CHUNK_SIZE);
    const base64Content = await FileSystem.readAsStringAsync(fullPath, {
      encoding: FileSystem.EncodingType.Base64,
      length: readSize,
    });

    if (!base64Content) return findings;

    // Decode base64 to byte array
    const bytes = base64ToBytes(base64Content);
    if (bytes.length < 4) return findings;

    // Check magic bytes against signature database
    const magicResult = checkMagicBytes(bytes, fullPath, sourceId);
    if (magicResult) {
      findings.push(createFinding({
        filename, fullPath, size, sourceId,
        title: `${magicResult.name}: ${filename}`,
        description: magicResult.description,
        severity: magicResult.severity as any,
        confidence: 80,
        evidence: [
          `Path: ${fullPath}`,
          `Size: ${formatSize(size)}`,
          `Header: ${bytesToHex(bytes.slice(0, 8))}`,
          `Detection: Magic byte signature match`,
        ],
        recommendation: 'This file contains executable code detected by binary header analysis. Delete unless you specifically placed it here.',
      }));
    }

    // Calculate Shannon entropy
    const entropy = calculateEntropy(bytes);
    if (entropy > ENTROPY_THRESHOLDS.encrypted) {
      findings.push(createFinding({
        filename, fullPath, size, sourceId,
        title: `Encrypted/packed payload: ${filename}`,
        description: `File has extremely high entropy (${entropy.toFixed(2)} bits/byte). This indicates encryption or packing — a technique malware uses to evade signature detection.`,
        severity: 'high',
        confidence: 70,
        evidence: [
          `Path: ${fullPath}`,
          `Size: ${formatSize(size)}`,
          `Entropy: ${entropy.toFixed(2)} bits/byte (threshold: ${ENTROPY_THRESHOLDS.encrypted})`,
          `Detection: Shannon entropy analysis`,
        ],
        recommendation: 'Encrypted payloads in non-standard locations are a strong malware indicator. Delete if you did not encrypt this file yourself.',
      }));
    } else if (entropy > ENTROPY_THRESHOLDS.packed && !isMediaFile(filename)) {
      findings.push(createFinding({
        filename, fullPath, size, sourceId,
        title: `Potentially packed file: ${filename}`,
        description: `File shows elevated entropy (${entropy.toFixed(2)} bits/byte) suggesting obfuscation or packing.`,
        severity: 'medium',
        confidence: 45,
        evidence: [
          `Path: ${fullPath}`,
          `Entropy: ${entropy.toFixed(2)} bits/byte`,
          `Detection: Entropy analysis`,
        ],
        recommendation: 'File may be obfuscated. Investigate if you do not recognize it.',
      }));
    }

    // Extract and check suspicious strings
    const textContent = extractPrintableStrings(bytes);
    const stringHits = checkSuspiciousStrings(textContent);
    if (stringHits.length > 0) {
      const topHit = stringHits[0]; // Most severe
      const allCategories = Array.from(new Set(stringHits.map((h) => h.category)));
      findings.push(createFinding({
        filename, fullPath, size, sourceId,
        title: `Malicious strings in: ${filename}`,
        description: `Found ${stringHits.length} suspicious string pattern(s): ${allCategories.join(', ')}. ${topHit.description}`,
        severity: topHit.severity as any,
        confidence: Math.min(90, 50 + stringHits.length * 15),
        evidence: [
          `Path: ${fullPath}`,
          `Size: ${formatSize(size)}`,
          ...stringHits.slice(0, 5).map((h) => `String match: ${h.name}`),
          `Detection: Embedded string analysis`,
        ],
        recommendation: 'File contains strings associated with malware behavior. Delete unless you are a developer who created this file.',
      }));
    }
  } catch {
    // Can't read file contents — skip deep analysis
  }

  return findings;
}

/**
 * Check file header bytes against known magic byte signatures.
 */
function checkMagicBytes(
  bytes: Uint8Array,
  fullPath: string,
  sourceId: string,
): { name: string; severity: string; description: string } | null {
  for (const sig of fileMagicSignatures) {
    // Only flag if the location matches threat context
    if (sig.threatIfLocation !== 'any' && sig.threatIfLocation !== sourceId) continue;

    // Check if magic bytes match at the specified offset
    if (bytes.length < sig.offset + sig.magicBytes.length) continue;

    let matches = true;
    for (let i = 0; i < sig.magicBytes.length; i++) {
      if (bytes[sig.offset + i] !== sig.magicBytes[i]) {
        matches = false;
        break;
      }
    }

    if (matches) {
      // APK signature: only flag if in cache/hidden locations (not downloads — user may have intentionally downloaded)
      if (sig.id === 'magic-apk' && sourceId === 'downloads' && !fullPath.includes('/.')) {
        continue; // Skip — user downloaded APK intentionally
      }
      return { name: sig.name, severity: sig.severity, description: sig.description };
    }
  }
  return null;
}

/**
 * Calculate Shannon entropy of a byte array.
 * High entropy = encrypted/compressed/random data.
 * Normal code/text = 4-5 bits/byte.
 * Encrypted payloads = 7.5+ bits/byte.
 */
function calculateEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;

  // Count byte frequencies
  const freq = new Array(256).fill(0);
  for (let i = 0; i < bytes.length; i++) {
    freq[bytes[i]]++;
  }

  // Calculate entropy
  let entropy = 0;
  const len = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Extract printable ASCII strings from binary data.
 * Looks for runs of 4+ printable characters.
 */
function extractPrintableStrings(bytes: Uint8Array): string {
  const strings: string[] = [];
  let current = '';

  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    // Printable ASCII range (32-126)
    if (b >= 32 && b <= 126) {
      current += String.fromCharCode(b);
    } else {
      if (current.length >= 4) {
        strings.push(current);
      }
      current = '';
    }
  }
  if (current.length >= 4) strings.push(current);

  return strings.join('\n');
}

/**
 * Check extracted strings against suspicious pattern database.
 */
function checkSuspiciousStrings(text: string): Array<{
  name: string;
  severity: string;
  description: string;
  category: string;
}> {
  const hits: Array<{ name: string; severity: string; description: string; category: string }> = [];

  for (const sig of suspiciousFileStrings) {
    try {
      const regex = new RegExp(sig.pattern, 'i');
      if (regex.test(text)) {
        hits.push({
          name: sig.name,
          severity: sig.severity,
          description: sig.description,
          category: sig.category,
        });
      }
    } catch {
      // Invalid regex — skip
    }
  }

  // Sort by severity (critical first)
  const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  hits.sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0));

  return hits;
}

// ─── Layer 3: Path-Based Heuristics ───────────────────────────

/**
 * Check file's full path against known malicious path patterns.
 */
function analyzeFilePath(
  fullPath: string,
  filename: string,
  size: number,
): ScanResult | null {
  for (const pathPattern of maliciousFilePathPatterns) {
    try {
      const regex = new RegExp(pathPattern.pattern, 'i');
      if (regex.test(fullPath)) {
        return createFinding({
          filename, fullPath, size, sourceId: 'path-analysis',
          title: `${pathPattern.name}: ${filename}`,
          description: pathPattern.description,
          severity: pathPattern.severity as any,
          confidence: 75,
          evidence: [
            `Path: ${fullPath}`,
            `Size: ${formatSize(size)}`,
            `Pattern: ${pathPattern.name}`,
            `Detection: Malicious path pattern match`,
          ],
          recommendation: 'File is in a path commonly used by malware. Investigate and delete if unrecognized.',
        });
      }
    } catch {
      // Invalid regex — skip
    }
  }
  return null;
}

// ─── Utility Functions ────────────────────────────────────────

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = new Uint8Array(256);
for (let i = 0; i < B64_CHARS.length; i++) B64_LOOKUP[B64_CHARS.charCodeAt(i)] = i;

function base64ToBytes(base64: string): Uint8Array {
  // Manual base64 decode — no reliance on global atob
  let len = base64.length;
  while (len > 0 && base64[len - 1] === '=') len--;

  const outLen = (len * 3) >>> 2;
  const bytes = new Uint8Array(outLen);

  let j = 0;
  for (let i = 0; i < len; i += 4) {
    const a = B64_LOOKUP[base64.charCodeAt(i)];
    const b = B64_LOOKUP[base64.charCodeAt(i + 1)];
    const c = B64_LOOKUP[base64.charCodeAt(i + 2)];
    const d = B64_LOOKUP[base64.charCodeAt(i + 3)];

    bytes[j++] = (a << 2) | (b >> 4);
    if (j < outLen) bytes[j++] = ((b & 0x0F) << 4) | (c >> 2);
    if (j < outLen) bytes[j++] = ((c & 0x03) << 6) | d;
  }

  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(' ');
}

function isMediaFile(filename: string): boolean {
  const ext = filename.toLowerCase().substring(filename.lastIndexOf('.'));
  const mediaExts = new Set(['.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.webm', '.ogg', '.wav', '.webp']);
  return mediaExts.has(ext);
}

/**
 * Deduplicate findings for the same file path.
 * When multiple layers detect the same file, merge evidence and take highest severity.
 */
function deduplicateFindings(findings: ScanResult[]): ScanResult[] {
  const byPath = new Map<string, ScanResult[]>();

  for (const f of findings) {
    const path = f.evidence?.[0] || f.id;
    const existing = byPath.get(path) || [];
    existing.push(f);
    byPath.set(path, existing);
  }

  const result: ScanResult[] = [];
  const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, safe: 0 };

  const entries = Array.from(byPath.values());
  for (const group of entries) {
    if (group.length === 1) {
      result.push(group[0]);
      continue;
    }

    // Merge: take highest severity, combine evidence, boost confidence
    group.sort((a: ScanResult, b: ScanResult) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0));
    const primary = { ...group[0] };
    const allEvidence = new Set<string>();
    let maxConfidence = primary.confidence || 50;

    for (const f of group) {
      f.evidence?.forEach((e: string) => allEvidence.add(e));
      maxConfidence = Math.max(maxConfidence, f.confidence || 50);
    }

    // Multi-indicator confidence boost
    primary.confidence = Math.min(98, maxConfidence + (group.length - 1) * 10);
    primary.evidence = Array.from(allEvidence);
    primary.description = `[${group.length} indicators] ${primary.description}`;
    result.push(primary);
  }

  return result;
}

function createFinding(params: {
  filename: string;
  fullPath: string;
  size: number;
  sourceId: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  evidence: string[];
  recommendation: string;
}): ScanResult {
  return {
    id: `file-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    moduleId: 'file-scanner',
    title: params.title,
    description: params.description,
    severity: params.severity,
    recommendation: params.recommendation,
    timestamp: Date.now(),
    evidence: params.evidence,
    confidence: params.confidence,
    agentId: 'file-scanner',
  };
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

/**
 * Get cache size for display.
 */
export async function getCacheSize(): Promise<string> {
  try {
    const cachePath = FileSystem.cacheDirectory;
    if (!cachePath) return '0 B';
    const info = await FileSystem.getInfoAsync(cachePath);
    if (info.exists && (info as any).size) return formatSize((info as any).size);
    return 'Unknown';
  } catch {
    return 'Unknown';
  }
}

/**
 * Get file scanner capabilities for display.
 */
export function getFileScanStats() {
  return {
    detectionLayers: 3,
    layerNames: ['Pattern matching', 'Binary analysis', 'Path heuristics'],
    magicSignatures: fileMagicSignatures.length,
    stringPatterns: suspiciousFileStrings.length,
    pathPatterns: maliciousFilePathPatterns.length,
    suspiciousExtensions: SUSPICIOUS_EXTENSIONS.size,
    knownMalwareFilenames: KNOWN_MALWARE_FILENAMES.size,
    capabilities: [
      'APK/DEX/ELF header detection',
      'Shannon entropy analysis (encrypted payload detection)',
      'Embedded C2 URL extraction',
      'Crypto stealer string detection',
      'Hidden directory detection',
      'Dropper stub identification',
      'Browser download scanning',
      'Multi-indicator confidence boosting',
    ],
  };
}

/**
 * Quick scan — only pattern matching, no file reading.
 * Fast but less thorough. Good for real-time monitoring.
 */
export async function quickScanFiles(
  targets?: FileScanTarget[],
  onProgress?: (progress: FileScanProgress) => void,
): Promise<ScanResult[]> {
  return scanFiles(targets, onProgress, false);
}

/**
 * Deep scan — full binary analysis including entropy and string extraction.
 * Slower but catches encrypted payloads and obfuscated malware.
 */
export async function deepScanFiles(
  targets?: FileScanTarget[],
  onProgress?: (progress: FileScanProgress) => void,
): Promise<ScanResult[]> {
  return scanFiles(targets, onProgress, true);
}
