# ShieldScan — Full Build Prompt

## What This Is

ShieldScan is a **real, working Android anti-spyware/malware scanner app** built with React Native + Expo SDK 55. It uses 8 local AI scanning agents, a 5-layer cloud AI fallback chain, optional on-device offline LLM, file scanning, forensic logging, and automated threat remediation.

**Build this as a complete Expo project. All code below is TypeScript strict mode. Target: Android APK via `eas build --platform android --profile preview`.**

---

## Tech Stack

- **Framework**: React Native 0.83 + Expo SDK 55 (New Architecture enabled)
- **Language**: TypeScript 5.9 (strict)
- **Navigation**: @react-navigation/bottom-tabs v7 + native-stack v7
- **Storage**: @react-native-async-storage/async-storage
- **Native Module**: Custom Java module (`ShieldScanModule.java`) via Expo native bridge
- **AI (cloud)**: Gemini 2.5 Flash, Groq Llama 3.3 70B, Zhipu GLM-4.7 Flash, DeepSeek R1 via OpenRouter
- **AI (offline)**: llama.rn (llama.cpp binding) with DeepSeek-R1-Distill-Qwen-1.5B GGUF
- **Notifications**: expo-notifications
- **File system**: expo-file-system (legacy API)

---

## Package.json Dependencies

```json
{
  "name": "shieldscan",
  "version": "1.0.0",
  "main": "index.ts",
  "scripts": {
    "start": "expo start",
    "android": "expo run:android",
    "ios": "expo run:ios"
  },
  "dependencies": {
    "@expo/vector-icons": "^15.1.1",
    "@react-native-async-storage/async-storage": "~2.1.0",
    "@react-navigation/bottom-tabs": "^7.16.1",
    "@react-navigation/native": "^7.2.4",
    "@react-navigation/native-stack": "^7.15.1",
    "expo": "~55.0.0",
    "expo-application": "^55.0.0",
    "expo-constants": "^55.0.0",
    "expo-device": "^55.0.0",
    "expo-file-system": "^55.0.0",
    "expo-linear-gradient": "^55.0.0",
    "expo-network": "^55.0.0",
    "expo-notifications": "^55.0.0",
    "expo-sqlite": "^55.0.0",
    "expo-status-bar": "~3.0.9",
    "llama.rn": "^0.12.0",
    "react": "19.2.0",
    "react-native": "0.83.1",
    "react-native-gesture-handler": "^2.31.2",
    "react-native-reanimated": "^4.3.1",
    "react-native-safe-area-context": "^5.7.0",
    "react-native-screens": "^4.25.0",
    "react-native-svg": "^15.15.5",
    "react-native-worklets": "^0.8.3"
  },
  "devDependencies": {
    "@types/react": "~19.1.0",
    "typescript": "~5.9.2"
  },
  "private": true
}
```

---

## app.json

```json
{
  "expo": {
    "name": "ShieldScan",
    "slug": "ShieldScan",
    "version": "1.0.0",
    "orientation": "portrait",
    "icon": "./assets/icon.png",
    "userInterfaceStyle": "dark",
    "newArchEnabled": true,
    "splash": {
      "image": "./assets/splash-icon.png",
      "resizeMode": "contain",
      "backgroundColor": "#02050A"
    },
    "android": {
      "package": "com.shieldscan.app",
      "versionCode": 1,
      "adaptiveIcon": {
        "foregroundImage": "./assets/adaptive-icon.png",
        "backgroundColor": "#02050A"
      },
      "permissions": [
        "android.permission.INTERNET",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.VIBRATE",
        "android.permission.WAKE_LOCK"
      ]
    },
    "plugins": [
      ["expo-notifications", { "icon": "./assets/icon.png", "color": "#00F5D4" }],
      "llama.rn"
    ],
    "extra": {
      "eas": { "projectId": "YOUR_PROJECT_ID" }
    }
  }
}
```

---

## eas.json

```json
{
  "cli": { "version": ">= 15.0.0", "appVersionSource": "remote" },
  "build": {
    "development": { "developmentClient": true, "distribution": "internal", "android": { "buildType": "apk" } },
    "preview": { "distribution": "internal", "android": { "buildType": "apk" } },
    "production": { "android": { "buildType": "app-bundle" } }
  }
}
```

---

## Project Structure

```
ShieldScan/
├── index.ts                          # Expo entry point
├── src/
│   ├── App.tsx                       # Root component (NavigationContainer + initLanguage)
│   ├── theme/
│   │   ├── index.ts                  # Re-exports colors, spacing, borderRadius
│   │   ├── colors.ts                 # Dark theme palette
│   │   ├── spacing.ts               # Spacing constants
│   │   └── typography.ts            # Font config
│   ├── types/
│   │   ├── engine.ts                 # ScanResult, ScanModule, RiskScore, SeverityLevel types
│   │   └── navigation.ts            # RootTabParamList (8 tabs)
│   ├── i18n/
│   │   ├── index.ts                  # t(), setLanguage(), getLanguage(), initLanguage()
│   │   ├── en.ts                     # English translations
│   │   └── nl.ts                     # Dutch translations
│   ├── data/
│   │   ├── modules.ts               # 8 scan modules definition (id, name, color, icon)
│   │   ├── signatures.ts            # Threat signature database (1,500+ patterns, 1,067 lines)
│   │   ├── threats.ts               # Threat family definitions
│   │   └── remediation.ts           # Remediation steps per threat type
│   ├── native/
│   │   └── NativeBridge.ts          # Bridge to ShieldScanModule.java (getInstalledApps, getRunningProcesses, getNetworkConnections, etc.)
│   ├── hooks/
│   │   ├── useScanEngine.ts         # Main scan orchestrator (8 agents + correlation)
│   │   └── useRemediation.ts        # Remediation hook
│   ├── utils/
│   │   ├── aiConfig.ts              # AI provider config (4 providers, keys in AsyncStorage)
│   │   ├── aiAnalysis.ts            # Cloud AI analysis (Gemini/Groq/GLM/OpenRouter fallback)
│   │   ├── aiOffline.ts             # On-device LLM via llama.rn (optional)
│   │   ├── fileScanner.ts           # Deep file scanner (3-layer: pattern + binary + path heuristics, 1,033 lines)
│   │   ├── cleanupEngine.ts         # Animated step-by-step threat cleanup
│   │   ├── quarantine.ts            # Quarantine management (AsyncStorage)
│   │   ├── threatTrace.ts           # IP geolocation + threat origin tracing
│   │   ├── forensicLog.ts           # Forensic event log (SHA-256 integrity)
│   │   ├── notifications.ts         # Push notification setup
│   │   ├── scheduler.ts             # Scan scheduling + history
│   │   └── reportExport.ts          # Export reports (text/HTML/JSON)
│   ├── components/common/
│   │   ├── GlassCard.tsx            # Glassmorphism card component
│   │   ├── SeverityBadge.tsx        # Critical/High/Medium/Low badge
│   │   ├── ProgressRing.tsx         # SVG circular progress ring
│   │   ├── ScanButton.tsx           # Animated scan trigger button
│   │   └── ScrollableTabBar.tsx     # Horizontal scrollable bottom tab bar (8 tabs)
│   ├── screens/
│   │   ├── HomeScreen.tsx           # Hero, module overview, trust badges
│   │   ├── ScannerScreen.tsx        # Main scanner (simplified one-button cleanup UX)
│   │   ├── RemoverScreen.tsx        # Threat removal dashboard
│   │   ├── IntelScreen.tsx          # Threat intelligence glossary
│   │   ├── ToolsScreen.tsx          # Security tools (Bluetooth, permissions, WebRTC, network)
│   │   ├── LiveProtectionScreen.tsx # Real-time monitoring (network, BT, app watcher)
│   │   ├── ForensicLogScreen.tsx    # Evidence chain log viewer
│   │   ├── AiAgentScreen.tsx       # On-device AI chat (real llama.rn inference + knowledge base fallback)
│   │   └── SettingsScreen.tsx       # All settings (schedule, notifications, AI config, offline model, language)
│   └── navigation/
│       └── AppNavigator.tsx         # Bottom tab navigator with ScrollableTabBar
└── android/
    └── app/src/main/java/com/shieldscan/app/
        └── ShieldScanModule.java    # Native Android module
```

---

## Architecture Overview

### 8 Scan Agents (all local, rule-based)

1. **Permissions Agent** — Detects dangerous permission combinations (e.g., CAMERA+RECORD_AUDIO+BOOT_COMPLETED = surveillance)
2. **Behavior Agent** — Flags apps with suspicious runtime behavior (background services, auto-start, overlay)
3. **Signature Agent** — Matches against 1,500+ known malware package patterns, C2 domains, YARA rules, and file signatures
4. **Network Agent** — Analyzes active network connections, flags suspicious remote IPs
5. **Integrity Agent** — Checks system integrity (root detection, ADB enabled, unknown sources)
6. **Adware/Stalkerware Agent** — Detects surveillance suites, accessibility abuse, silent GPS trackers
7. **Data Exfiltration Agent** — Detects data harvesters, file theft, social graph scraping
8. **Cryptojacking/Fraud Agent** — Detects premium SMS fraud, toll fraud, dropper capability, crypto mining

### Cross-Agent Correlation Engine

After all 8 agents run, the correlation engine:
- Groups findings by `packageName`
- If 2+ agents flag same package → severity boosted
- If 3+ agents flag same package → severity = critical
- Calculates cross-agent confidence (avg + 8% per agreeing agent, capped 99%)

### AI Analysis (5-layer fallback, all free)

```
① On-device DeepSeek-R1 1.5B (offline, optional, user downloads ~1.1GB model)
② Google Gemini 2.5 Flash (15 RPM, 1,500 req/day, 1M context)
③ Groq Llama 3.3 70B (30 RPM, 1K req/day, ultra-fast LPU)
④ Zhipu GLM-4.7 Flash (1,000 req/day, 200K context, MIT license)
⑤ DeepSeek R1 671B via OpenRouter (20 RPM, 200 req/day, best reasoning)
```

- User must explicitly opt-in (consent toggle, default OFF)
- Only anonymized data sent (permission names, severity levels, generic descriptions)
- No device IDs, no PII, no package names leave the device
- Each provider has its own API key (user gets free from provider sites)

### File Scanner (Deep 3-Layer Analysis)

Multi-layer detection engine — works without AI, pure deterministic analysis:

**Layer 1: Pattern Matching**
- Extension detection (`.apk`, `.dex`, `.jar`, `.class`, `.sh`, `.so`, `.war`, `.enc`, etc.)
- Known malware filenames (100% confidence: `b.dex`, `payload.jar`, `stolen_cookies.txt`, etc.)
- Suspicious filename regex (payload, exploit, keylog, stage1, c2config, etc.)
- Dropper stub detection (APKs under 50KB)
- Java threat files (`.class`/`.jar`/`.war` should NEVER exist on Android)
- Stolen browser database files outside browser dirs (`cookies.db`, `Login Data`, `logins.json`)

**Layer 2: Binary Analysis (Deep Scan)**
- Magic byte detection (DEX `0x6465780A`, ELF `0x7F454C46`, Java class `0xCAFEBABE`, shell `0x23212F`, SQLite, GZip)
- Shannon entropy calculation (>7.5 = encrypted payload, >6.8 = packed/obfuscated)
- Embedded string extraction (pulls printable ASCII from binaries)
- C2 URL detection (hardcoded IPs, DuckDNS, Ngrok, Telegram bot tokens, Discord webhooks)
- Exploit strings (JNDI, Runtime.exec, DexClassLoader, deserialization gadgets)
- Cookie/session theft strings (CookieManager, document.cookie, PHPSESSID, browser profile paths)
- Crypto stealer strings (seed phrase, mnemonic, wallet addresses)

**Layer 3: Path Heuristics**
- Hidden dot-directories with executables inside (critical)
- Malware staging paths (`/sdcard/.hidden/`, `/data/local/tmp/*.dex`)
- Browser download scanning (Chrome, Firefox, Brave, Opera, Samsung Internet, Edge, UC Browser)
- Crypto miner artifacts (pool config, xmrig binaries)

**Multi-Indicator Confidence Boosting:**
- Same file flagged by multiple layers → findings merged, confidence boosted (+10% per layer)
- Deduplication engine prevents duplicate alerts

**Scan Modes:**
- `quickScanFiles()` — pattern only (fast)
- `deepScanFiles()` — full binary analysis (thorough)

### Cleanup Engine (one-button UX)

User presses "Handle All Threats" → picks cleanup style:

- **Quick Clean**: Quarantine + disable
- **Deep Clean**: Revoke admin → force-stop → clear data → disable (prevents reinstall)
- **Nuclear Clean**: All above + uninstall + delete related files

Animated step-by-step progress with deliberate pacing:
- Shows each action: "Revoking permissions...", "Force stopping...", "Clearing data..."
- Progress bar + current step detail
- Completed steps show checkmarks
- Slow enough for user to feel the app is working hard

### Recurrence Detection

- After cleanup, cleaned threats are recorded (package name + timestamp)
- On next scan, if same package reappears → flagged as `[RECURRENT]`
- Recurrent threats get severity boost (low→medium, medium→high, high→critical)
- Banner shows "X threats have reappeared after previous cleanup"

### Forensic Log

- SHA-256 integrity hash per entry (law enforcement grade)
- Categories: threats, connections, apps, system
- Export: JSON, CSV, text report
- "Share with Authorities" button
- Max 500 entries FIFO

### Threat Signature Database (`signatures.ts` — 1,520 lines)

Massive offline signature database containing:

| Category | Count | What It Detects |
|---|---|---|
| Package patterns | ~160 | Known malware families, disguised system apps, stalkerware, Java RATs |
| C2/infrastructure | ~120 | Command servers, exfil endpoints, DGA domains, tunnel services |
| Permission combos | ~25 | Dangerous perm sets (surveillance, banking trojan, sextortion, cookie theft) |
| Behavioral indicators | ~30 | Hidden icons, battery drain, accessibility abuse, camera after adult content |
| YARA rules | ~45 | String matching for malware families (2024-2026 threats included) |
| File magic signatures | 9 | Binary header detection (DEX, ELF, Java class, shell, SQLite, ZIP/JAR) |
| Suspicious strings | ~50 | C2 URLs, exploit code, cookie theft, crypto targeting, evasion, adult threats |
| Path patterns | 10 | Staging directories, hidden folders, miner configs |
| Persistence indicators | 8 | Companion installers, boot scripts, device admin abuse |
| Cert fingerprints | 10 | Known malware signing certificate prefixes |

**Threat families covered (2024-2026):**
- Banking: Mamont, ToxicPanda, Nexus, GodFather, Hook, Octo2, Zanubis, PixPirate
- Spyware: SparkCat, LunaSpy, Mandrake, VajraSpy, Rafel RAT, Predator, Pegasus
- Java: jRAT, Adwind, Log4Shell, Spring4Shell, Java deserialization exploits
- Cookie theft: Raccoon, RedLine, Vidar, Lumma Stealer, Aurora, CookieMonster
- Adult/porn: AdultPlayer ransomware, PornDroid, Koler, Sextortion, Leakware, FakeCodec
- Adware: MobiDash, Adlo, HiddenAd, FakeCleaner
- Fraud: SpyLoan, Joker, Harly, Fleckpe, Goldoson

**Key exports:**
```typescript
export const maliciousPackagePatterns: {...}[]
export const maliciousInfrastructure: {...}[]
export const expandedDangerousPermCombos: {...}[]
export const behavioralIndicators: {...}[]
export const yaraRules: {...}[]
export const fileMagicSignatures: FileMagicSignature[]
export const suspiciousFileStrings: SuspiciousString[]
export const maliciousFilePathPatterns: MaliciousPathPattern[]
export const persistenceIndicators: PersistenceIndicator[]
export const maliciousCertFingerprints: {...}[]
export const ENTROPY_THRESHOLDS: { encrypted: 7.5, packed: 6.8, suspicious: 6.0, normal: 4.5 }
export function lookupPackage(packageName: string): { matched, family?, severity?, description? }
export function lookupDomain(domain: string): { matched, type?, family? }
export function lookupIP(ip: string): { matched, type?, family? }
```

### AI Chat Screen (`AiAgentScreen.tsx`)

Full on-device conversational AI using the downloaded model:

**When model is available:**
- Real inference via llama.rn with ChatML format
- Security-specialized system prompt
- Conversation history (last 6 messages) in context
- Last scan results injected automatically
- "Thinking..." streaming indicator
- Stop button for long responses
- Status: green dot "On-device model active"

**When model not downloaded (fallback):**
- Intelligent knowledge-base responses (10+ categories hardcoded)
- Covers: scan results, cookies, Java threats, porn/sextortion, permissions, VPN, cleanup, stalkerware
- Status: orange dot "Knowledge base mode"
- Prompts user to download model for full AI

**Chat system prompt:**
```
You are ShieldScan AI — a mobile security assistant running 100% on-device.
You help users understand threats, explain scan results, give security advice,
and answer questions about phone safety. You are privacy-focused, direct, and
technically accurate. Keep answers concise (2-4 sentences unless asked for detail).
Never suggest sending data to external services.
```

---

## Key Design Principles

1. **Dark theme only** — Deep black (#02050A) background, glassmorphism cards, mint (#00F5D4) accent
2. **Privacy first** — Everything runs locally by default. Cloud AI is opt-in with explicit consent.
3. **No Barnum effect** — Findings are specific, evidence-based, never generic scare tactics
4. **Samsung A53 target** — 6GB RAM, must fit 8 tabs (ScrollableTabBar component)
5. **Deliberate UX pacing** — Cleanup animations are intentionally 800ms per step so user sees work happening
6. **Simplified interaction** — One button to handle all threats, user picks style, app does the rest

---

## Native Module (ShieldScanModule.java)

The native Java module provides these methods via NativeModules bridge:

```java
// Methods exposed to React Native:
getInstalledApps()        // Returns JSON array of all installed packages with permissions
getRunningProcesses()     // Returns JSON array of running processes with memory usage
getNetworkConnections()   // Returns JSON array of active TCP/UDP connections
getDeviceInfo()           // Returns device security state (root, ADB, unknown sources)
requestUninstall(pkg)     // Opens system uninstall dialog for a package
openAppSettings(pkg)      // Opens system app info page for a package
```

Uses `android.permission.QUERY_ALL_PACKAGES` to enumerate all apps.

---

## Color Palette

```typescript
const colors = {
  bgDeep: '#02050A',
  bgSurface: '#0A0F1A',
  bgGlass: 'rgba(255,255,255,0.03)',
  glassBorder: 'rgba(255,255,255,0.06)',
  textPrimary: '#E8ECF1',
  textSecondary: '#8B95A5',
  textMuted: '#4A5568',
  accentMint: '#00F5D4',
  accentWarning: '#FF9500',
  accentDanger: '#FF3B5C',
  accentInfo: '#5AC8FA',
  accentOrange: '#FF6B35',
  accentSuccess: '#34C759',
  ringTrack: 'rgba(255,255,255,0.06)',
  severity: {
    critical: '#FF3B5C',
    high: '#FF6B35',
    medium: '#FF9500',
    low: '#5AC8FA',
    safe: '#34C759',
  },
};
```

---

## AI Provider API Details

### Gemini 2.5 Flash
- Endpoint: `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={KEY}`
- Body: `{ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.3, maxOutputTokens: 4096, responseMimeType: 'application/json' } }`
- Free key: https://aistudio.google.com/apikey

### Groq Llama 3.3 70B
- Endpoint: `https://api.groq.com/openai/v1/chat/completions`
- Auth: `Bearer {KEY}`
- Body: `{ model: 'llama-3.3-70b-versatile', messages: [...], temperature: 0.3, max_tokens: 4096, response_format: { type: 'json_object' } }`
- Free key: https://console.groq.com/keys

### Zhipu GLM-4.7 Flash
- Endpoint: `https://open.bigmodel.cn/api/paas/v4/chat/completions`
- Auth: `Bearer {KEY}`
- Body: `{ model: 'glm-4-flash', messages: [...], temperature: 0.3, max_tokens: 4096 }`
- Free key: https://open.bigmodel.cn

### OpenRouter (DeepSeek R1)
- Endpoint: `https://openrouter.ai/api/v1/chat/completions`
- Auth: `Bearer {KEY}`, Headers: `HTTP-Referer: https://shieldscan.app`, `X-Title: ShieldScan`
- Body: `{ model: 'deepseek/deepseek-r1:free', messages: [...], temperature: 0.3, max_tokens: 4096 }`
- Free key: https://openrouter.ai/keys

### On-Device (llama.rn)
- Model: DeepSeek-R1-Distill-Qwen-1.5B-Q4_K_M.gguf (~1.1GB download)
- URL: `https://huggingface.co/bartowski/DeepSeek-R1-Distill-Qwen-1.5B-GGUF/resolve/main/DeepSeek-R1-Distill-Qwen-1.5B-Q4_K_M.gguf`
- Config: `{ n_ctx: 2048, n_batch: 256, n_threads: 4, use_mmap: true }`
- Uses ChatML prompt format (`<|im_start|>system...`)
- Optional — user must enable + download (resource disclosure shown first)

---

## AI Prompt Template

```
You are a mobile security analyst. Analyze these Android device scan findings and provide actionable threat intelligence.

SCAN SUMMARY:
- Total findings: {count}
- Risk score: {score}/100 ({level})
- Critical: {n} | High: {n} | Medium: {n} | Low: {n}

FINDINGS:
[1] [CRITICAL] [permissions] Surveillance Permission Suite
  App has CAMERA+RECORD_AUDIO+ACCESS_FINE_LOCATION+RECEIVE_BOOT_COMPLETED+INTERNET
  Evidence: [package], Boot receiver, GPS access
  CORRELATED: Multiple agents flagged this
  Confidence: 82%

Respond in this exact JSON format:
{
  "summary": "2-3 sentence overall threat assessment",
  "overallAssessment": "paragraph about security posture",
  "insights": [{
    "findingIndex": 1,
    "analysis": "what this means in plain language",
    "riskExplanation": "why this is dangerous",
    "attackVector": "how an attacker could exploit this",
    "priority": "immediate|high|moderate|low",
    "remediationSteps": ["step 1", "step 2"]
  }]
}

Focus on the top 10 most critical findings. Be specific, not generic. No Barnum statements.
```

---

## Build Instructions

```bash
# Install dependencies
npm install

# Generate native Android project
npx expo prebuild --platform android --clean

# Build APK (requires EAS login or local JDK 17)
eas build --platform android --profile preview

# OR local build (requires JAVA_HOME set to JDK 17):
cd android && ./gradlew assembleRelease
# APK output: android/app/build/outputs/apk/release/app-release.apk
```

---

## Key Implementation Notes

1. **ScrollableTabBar**: Custom bottom tab bar with horizontal ScrollView for 8 tabs on small screens. TAB_MIN_WIDTH = 68px. Auto-scrolls to active tab.

2. **Scan Engine**: `useScanEngine` hook runs all 8 agents sequentially, reports progress per module. After all complete, correlation engine runs, then risk score calculated.

3. **Risk Score**: 0-100 scale. `breakdown` is `Record<string, number>` with per-module scores. Level: safe (<20), low (20-40), medium (40-60), high (60-80), critical (80+).

4. **Anonymization**: Before sending to cloud AI, package names are stripped with regex `/[a-z]+\.[a-z]+\.[a-z]+[.\w]*/gi` → `[package]`. No PII leaves device.

5. **Consent model**: AI analysis (cloud) requires explicit toggle ON in Settings. Default is OFF. Offline AI has separate consent with resource disclosure alert.

6. **AsyncStorage keys**:
   - `@shieldscan_language` (en/nl)
   - `@shieldscan_ai_consent` (true/false)
   - `@shieldscan_ai_gemini_key`, `_groq_key`, `_glm_key`, `_openrouter_key`
   - `@shieldscan_offline_ai_enabled`, `@shieldscan_offline_model_ready`
   - `@shieldscan_quarantine` (JSON array)
   - `@shieldscan_forensic_log` (JSON array)
   - `@shieldscan_scan_history` (JSON array)
   - `@shieldscan_scan_schedule` (JSON object)
   - `@shieldscan_cleaned_threats` (for recurrence detection)
   - `@shieldscan_custom_scan_folders`

7. **Forensic Log**: Each entry gets SHA-256 hash of (previous_hash + entry_json) for tamper detection. Max 500 entries.

8. **Cleanup pacing**: 800ms delay between steps. Steps show "Analyzing...", "Revoking permissions...", "Force stopping...", "Clearing data...", "Verifying..." — deliberate UX so user sees work happening.

9. **File Scanner binary analysis**: Uses `FileSystem.readAsStringAsync(path, { encoding: Base64, length: 4096 })` to read first 4KB. Custom base64→bytes decoder (no atob dependency). Shannon entropy on byte frequency array. String extraction via printable ASCII run detection (4+ chars).

10. **AI Chat**: When model available, creates fresh `initLlama` context per message (releases after response to free RAM). ChatML format with 6-message history window. 512 token max response. When model unavailable, falls back to hardcoded category-based responses that still feel intelligent.

11. **Java threat detection**: `.class`/`.jar`/`.war` files are ALWAYS flagged as critical on Android because Android uses DEX bytecode, not Java class files. Any Java bytecode file on the device is a cross-platform RAT payload (jRAT/Adwind/QRAT).

12. **Cookie theft detection**: Browser DB filenames (`Cookies`, `Login Data`, `logins.json`, `key3.db`, `signons.sqlite`) found outside legitimate browser app directories (`com.android.chrome`, `org.mozilla.firefox`, etc.) are flagged as stolen credential databases.

13. **Adult site threats**: Covers ransomware (device lock + camera capture + fake police warning), sextortion (gallery scan + contacts + blackmail), fake codecs/players (APK droppers from porn sites), aggressive adware from malvertising redirects.

---

## What To Build

Build ALL files listed in the project structure above. Every screen, every utility, every component. This is a production app, not a prototype. The scanner must actually:
- Read installed apps via the native module
- Analyze permissions against 25+ known dangerous combinations
- Match package names against 160+ malware family patterns
- Check network connections against 120+ C2/infrastructure domains
- Flag recurrent threats that reappear after cleanup
- Deep-scan files with 3-layer analysis (pattern → binary → path)
- Detect Java threats (.class/.jar should never exist on Android)
- Detect stolen browser cookies/sessions outside browser directories
- Detect adult site malware (ransomware, sextortion, fake players)
- Calculate Shannon entropy to find encrypted payloads
- Extract embedded strings from binaries (C2 URLs, crypto addresses, exploit patterns)
- Provide one-button cleanup with animated progress
- Support 5-layer AI analysis (offline first, then cloud fallback)
- Real AI chat screen using on-device model (with knowledge-base fallback)

### New AsyncStorage Keys (added)
- `@shieldscan_last_scan_summary` (used by AI chat for scan context)

Make it build-ready with `eas build --platform android --profile preview`.
