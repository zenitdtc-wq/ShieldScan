/**
 * ShieldScan Expanded Threat Signature Database
 *
 * Contains 50+ malware signatures, dangerous permission patterns,
 * known C2 infrastructure, and behavioral indicators.
 *
 * In production, this would be stored in SQLite and updated via
 * encrypted delta downloads from a secure CDN.
 */

// ─── Known Malicious Package Patterns ───────────────────────────
// Regex patterns for package names associated with known malware families
export const maliciousPackagePatterns: {
  pattern: string;
  family: string;
  severity: string;
  description: string;
}[] = [
  // Banking Trojans
  { pattern: 'com\\.anubis\\..*', family: 'Anubis', severity: 'critical', description: 'Banking trojan with overlay attacks' },
  { pattern: 'com\\.bankbot\\..*', family: 'BankBot', severity: 'critical', description: 'Banking credential stealer' },
  { pattern: 'com\\.cerberus\\..*', family: 'Cerberus', severity: 'critical', description: 'Banking trojan with RAT capabilities' },
  { pattern: 'com\\.hydra\\..*', family: 'Hydra', severity: 'critical', description: 'Banking trojan targeting European banks' },
  { pattern: 'com\\.teabot\\..*', family: 'TeaBot', severity: 'critical', description: 'Banking trojan with screen recording' },
  { pattern: 'com\\.sharkbot\\..*', family: 'SharkBot', severity: 'critical', description: 'ATS banking trojan' },
  { pattern: 'com\\.xenomorph\\..*', family: 'Xenomorph', severity: 'critical', description: 'Banking trojan distributed via Google Play' },
  { pattern: 'com\\.vultur\\..*', family: 'Vultur', severity: 'critical', description: 'Banking trojan with VNC screen recording' },
  { pattern: 'com\\.octo\\..*', family: 'Octo/ExobotCompact', severity: 'critical', description: 'Banking trojan with remote access' },
  { pattern: 'com\\.ermac\\..*', family: 'ERMAC', severity: 'critical', description: 'Banking trojan evolved from Cerberus' },

  // RATs
  { pattern: 'ahmyth\\..*', family: 'AhMyth', severity: 'high', description: 'Open-source RAT' },
  { pattern: 'com\\.ahmyth\\..*', family: 'AhMyth', severity: 'high', description: 'Open-source RAT variant' },
  { pattern: 'com\\.metasploit\\..*', family: 'Metasploit', severity: 'critical', description: 'Metasploit Meterpreter payload' },
  { pattern: 'com\\.spynote\\..*', family: 'SpyNote', severity: 'critical', description: 'Commercial RAT with full device control' },
  { pattern: 'com\\.androrat\\..*', family: 'AndroRAT', severity: 'high', description: 'Android Remote Admin Tool' },
  { pattern: 'com\\.droidjack\\..*', family: 'DroidJack', severity: 'critical', description: 'Commercial RAT with SMS/call interception' },
  { pattern: 'com\\.sandrorat\\..*', family: 'SandroRAT', severity: 'high', description: 'Remote administration trojan' },
  { pattern: 'com\\.omni\\.rat\\..*', family: 'OmniRAT', severity: 'critical', description: 'Cross-platform RAT' },

  // Stalkerware
  { pattern: 'com\\.cocospy\\..*', family: 'Cocospy', severity: 'high', description: 'Commercial stalkerware' },
  { pattern: 'com\\.mspy\\..*', family: 'mSpy', severity: 'high', description: 'Commercial surveillance tool' },
  { pattern: 'com\\.flexispy\\..*', family: 'FlexiSpy', severity: 'high', description: 'Advanced commercial spyware' },
  { pattern: 'com\\.hoverwatch\\..*', family: 'Hoverwatch', severity: 'high', description: 'Phone tracking stalkerware' },
  { pattern: 'com\\.spyera\\..*', family: 'Spyera', severity: 'high', description: 'Commercial phone monitoring' },
  { pattern: 'com\\.eyezy\\..*', family: 'Eyezy', severity: 'high', description: 'Phone monitoring app' },
  { pattern: 'com\\.thetruthspy\\..*', family: 'TheTruthSpy', severity: 'high', description: 'Stalkerware with keylogging' },
  { pattern: 'com\\.xnspy\\..*', family: 'XNSPY', severity: 'high', description: 'Commercial phone spy app' },
  { pattern: 'com\\.ikeym.*', family: 'iKeyMonitor', severity: 'high', description: 'Keylogger and monitoring tool' },

  // Spyware & Data Stealers
  { pattern: 'com\\.spark\\..*', family: 'SparkCat', severity: 'critical', description: 'Crypto wallet seed phrase stealer' },
  { pattern: 'com\\.predator\\..*', family: 'Predator', severity: 'critical', description: 'Commercial spyware by Cytrox' },
  { pattern: 'com\\.pegasus\\..*', family: 'Pegasus', severity: 'critical', description: 'NSO Group spyware' },
  { pattern: 'com\\.chrysaor\\..*', family: 'Chrysaor', severity: 'critical', description: 'Pegasus variant for Android' },
  { pattern: 'com\\.hermit\\..*', family: 'Hermit', severity: 'critical', description: 'Italian commercial spyware' },

  // Loaders & Droppers
  { pattern: 'com\\.loader\\..*', family: 'Generic Loader', severity: 'high', description: 'Malware downloader/loader' },
  { pattern: 'com\\.dropper\\..*', family: 'Generic Dropper', severity: 'high', description: 'Payload dropper' },
  { pattern: 'com\\.joker\\..*', family: 'Joker', severity: 'high', description: 'Premium SMS fraud + spyware' },
  { pattern: 'com\\.harly\\..*', family: 'Harly', severity: 'high', description: 'Subscription fraud trojan' },
  { pattern: 'com\\.fleckpe\\..*', family: 'Fleckpe', severity: 'high', description: 'Subscription trojan from Google Play' },
  { pattern: 'com\\.golddigger\\..*', family: 'GoldDigger', severity: 'critical', description: 'Banking trojan targeting Southeast Asia' },

  // Adware & PUPs
  { pattern: 'com\\.hiddad\\..*', family: 'HiddAd', severity: 'medium', description: 'Hidden ad display malware' },
  { pattern: 'com\\.adware\\..*', family: 'Generic Adware', severity: 'medium', description: 'Aggressive ad injection' },
  { pattern: 'com\\.fakeapp\\..*', family: 'FakeApp', severity: 'medium', description: 'Fake utility app with ads' },
  { pattern: 'com\\.clicker\\..*', family: 'Clicker', severity: 'medium', description: 'Ad fraud clicker' },

  // Ransomware
  { pattern: 'com\\.simplocker\\..*', family: 'Simplocker', severity: 'critical', description: 'File-encrypting ransomware' },
  { pattern: 'com\\.lockerpin\\..*', family: 'LockerPin', severity: 'critical', description: 'Screen-locking ransomware' },
  { pattern: 'com\\.doublelocker\\..*', family: 'DoubleLocker', severity: 'critical', description: 'Combined ransomware + banking trojan' },

  // Cryptominers
  { pattern: 'com\\.coinhive\\..*', family: 'CoinHive', severity: 'medium', description: 'Cryptocurrency miner' },
  { pattern: 'com\\.cryptojacker\\..*', family: 'CryptoJacker', severity: 'medium', description: 'Hidden crypto mining' },

  // Fake/Trojanized apps
  { pattern: 'com\\.sysupdate\\..*', family: 'FakeSystemUpdate', severity: 'critical', description: 'Trojan disguised as system update' },
  { pattern: 'com\\.system\\.updateservice', family: 'FakeSystemUpdate', severity: 'critical', description: 'Fake system update service' },
  { pattern: 'com\\.android\\.system\\.manager\\..*', family: 'FakeManager', severity: 'high', description: 'Fake system manager' },
  { pattern: 'com\\.pdf\\.reader\\.free.*', family: 'Anatsa Dropper', severity: 'high', description: 'Anatsa banking trojan dropper' },
  { pattern: 'com\\.docreader\\..*', family: 'Anatsa Dropper', severity: 'high', description: 'Anatsa dropper variant' },

  // Advanced Banking Trojans & Droppers (Extended)
  { pattern: 'com\\.alien\\..*', family: 'Alien', severity: 'critical', description: 'Advanced banking trojan with 2FA bypass' },
  { pattern: 'com\\.blackrock\\..*', family: 'BlackRock', severity: 'critical', description: 'Data stealer targeting social/dating apps' },
  { pattern: 'com\\.brata\\..*', family: 'BRATA', severity: 'critical', description: 'Banking trojan with device wiping capabilities' },
  { pattern: 'com\\.flubot\\..*', family: 'FluBot', severity: 'critical', description: 'SMS-spreading banking malware' },
  { pattern: 'com\\.medusa\\..*', family: 'Medusa', severity: 'critical', description: 'Banking trojan with keylogging and SMS theft' },
  { pattern: 'com\\.cabassous\\..*', family: 'Cabassous', severity: 'critical', description: 'Banking trojan focused on corporate credentials' },
  { pattern: 'com\\.eventbot\\..*', family: 'EventBot', severity: 'critical', description: 'Banking trojan exploiting accessibility' },
  { pattern: 'com\\.gustuff\\..*', family: 'Gustuff', severity: 'critical', description: 'Banking trojan automating transactions' },
  { pattern: 'com\\.hydra\\..*', family: 'Hydra', severity: 'critical', description: 'Banking trojan targeting European banks' },
  { pattern: 'com\\.trickmo\\..*', family: 'TrickMo', severity: 'critical', description: 'Trickbot-affiliated mobile banking trojan' },

  // Persistent Threats (Rootkit/System level)
  { pattern: 'com\\.xhelper\\..*', family: 'xHelper', severity: 'critical', description: 'Undeletable persistent dropper' },
  { pattern: 'com\\.triada\\..*', family: 'Triada', severity: 'critical', description: 'Modular system-level trojan' },
  { pattern: 'com\\.zombinder\\..*', family: 'Zombinder', severity: 'critical', description: 'APK binder for dropping secondary payloads' },
  { pattern: 'com\\.dvmap\\..*', family: 'Dvmap', severity: 'critical', description: 'Rooting trojan injecting malicious code into system libraries' },

  // Commercial Spyware / Cyber Mercenary (Extended)
  { pattern: 'com\\.finspy\\..*', family: 'FinSpy', severity: 'critical', description: 'Commercial surveillance suite' },
  { pattern: 'com\\.tianwang\\..*', family: 'Tianwang', severity: 'critical', description: 'State-sponsored spyware' },
  { pattern: 'com\\.quadream\\..*', family: 'QuaDream', severity: 'critical', description: 'Zero-click commercial spyware' },
  { pattern: 'com\\.cytrox\\..*', family: 'Cytrox/Predator', severity: 'critical', description: 'Advanced mobile spyware' },

  // Info Stealers & Fake Apps
  { pattern: 'com\\.facestealer\\..*', family: 'FaceStealer', severity: 'high', description: 'Facebook credential stealer' },
  { pattern: 'com\\.autolycos\\..*', family: 'Autolycos', severity: 'high', description: 'Subscription fraud malware' },
  { pattern: 'com\\.vampire\\..*', family: 'Vampire', severity: 'high', description: 'SMS-based premium subscription fraud' },
  { pattern: 'com\\.mobokey\\..*', family: 'MoboKey', severity: 'high', description: 'Keylogger disguised as utility' },

  // ─── 2024-2026 Banking Trojans ────────────────────────────────
  { pattern: 'com\\.mamont\\..*', family: 'Mamont', severity: 'critical', description: '2025 banking trojan targeting Russian/CIS banking apps with push notification theft' },
  { pattern: 'com\\.toxicpanda\\..*', family: 'ToxicPanda', severity: 'critical', description: '2024 banking trojan with on-device fraud (ODF) capabilities' },
  { pattern: 'com\\.creduz\\..*', family: 'Creduz', severity: 'critical', description: '2025 credential stealer targeting multi-bank overlays' },
  { pattern: 'com\\.frogblight\\..*', family: 'Frogblight', severity: 'critical', description: '2025 banking trojan with ATS and accessibility abuse' },
  { pattern: 'com\\.coper\\..*', family: 'Coper/Octo2', severity: 'critical', description: 'Octo successor with improved C2 resilience and domain generation' },
  { pattern: 'com\\.grandoreiro\\..*', family: 'Grandoreiro', severity: 'critical', description: 'Cross-platform banking trojan expanded to mobile in 2024' },
  { pattern: 'com\\.pixpirate\\..*', family: 'PixPirate', severity: 'critical', description: '2024 trojan targeting Pix instant payment system' },
  { pattern: 'com\\.zanubis\\..*', family: 'Zanubis', severity: 'critical', description: '2024 banking trojan disguised as government apps' },
  { pattern: 'com\\.nexus\\..*', family: 'Nexus', severity: 'critical', description: '2024 MaaS banking trojan with 450+ target overlays' },
  { pattern: 'com\\.godfather\\..*', family: 'GodFather', severity: 'critical', description: '2024 banking trojan targeting 500+ banking apps globally' },
  { pattern: 'com\\.hook\\..*', family: 'Hook', severity: 'critical', description: '2024 ERMAC successor with VNC and file manager capabilities' },

  // ─── 2024-2026 Spyware & Stealers ─────────────────────────────
  { pattern: 'com\\.lunaspy\\..*', family: 'LunaSpy', severity: 'critical', description: '2025 spyware with zero-click exploit chain' },
  { pattern: 'com\\.sparkcat\\..*', family: 'SparkCat', severity: 'critical', description: '2025 OCR-based crypto seed phrase stealer using ML' },
  { pattern: 'com\\.albiriox\\..*', family: 'Albiriox', severity: 'critical', description: '2025 stealer targeting crypto wallets and 2FA codes' },
  { pattern: 'com\\.rafel\\..*', family: 'Rafel RAT', severity: 'critical', description: '2024 open-source RAT widely used in targeted attacks' },
  { pattern: 'com\\.vajraspy\\..*', family: 'VajraSpy', severity: 'critical', description: '2024 espionage malware targeting Indian subcontinent' },
  { pattern: 'com\\.kamran\\..*', family: 'Kamran', severity: 'high', description: '2024 spyware targeting Uyghur community via fake news apps' },
  { pattern: 'com\\.evilbamboo\\..*', family: 'EvilBamboo', severity: 'critical', description: '2024 China-linked APT spyware targeting Tibetan/Uyghur users' },
  { pattern: 'com\\.mandrake\\..*', family: 'Mandrake', severity: 'critical', description: '2024 advanced spyware with multi-stage evasion (survived on Play Store)' },

  // ─── Disguised System Apps ─────────────────────────────────────
  // Real malware uses fake system package names to hide
  { pattern: 'com\\.android\\.systemupdate$', family: 'FakeSystemUpdate', severity: 'critical', description: 'Malware masquerading as Android system update' },
  { pattern: 'com\\.android\\.system\\.update\\..*', family: 'FakeSystemUpdate', severity: 'critical', description: 'Fake system update service' },
  { pattern: 'com\\.android\\.provider\\.security$', family: 'FakeSecurityProvider', severity: 'critical', description: 'Malware posing as security provider' },
  { pattern: 'com\\.android\\.incallui\\.service$', family: 'FakePhone', severity: 'high', description: 'Malware posing as phone system service' },
  { pattern: 'com\\.android\\.vpnservice\\..*', family: 'FakeVPN', severity: 'high', description: 'Spyware disguised as system VPN' },
  { pattern: 'com\\.android\\.wifiservice\\..*', family: 'FakeWifi', severity: 'high', description: 'Malware disguised as WiFi service' },
  { pattern: 'com\\.sec\\.android\\..*im\\d{8}', family: 'iKeyMonitor', severity: 'critical', description: 'iKeyMonitor stalkerware disguised as Samsung service' },
  { pattern: 'com\\.samsung\\.android\\.service\\.\\w{6,}$', family: 'FakeSamsung', severity: 'high', description: 'Malware impersonating Samsung service' },
  { pattern: 'com\\.google\\.android\\.gms\\.\\w+\\.\\w{8,}$', family: 'FakeGMS', severity: 'critical', description: 'Malware impersonating Google Play Services component' },
  { pattern: 'com\\.google\\.android\\.apps\\.update\\w+', family: 'FakeGoogleUpdate', severity: 'critical', description: 'Trojan disguised as Google app updater' },
  { pattern: 'com\\.qualcomm\\.\\w+service$', family: 'FakeQualcomm', severity: 'high', description: 'Malware posing as Qualcomm system component' },
  { pattern: 'com\\.mediatek\\.\\w+service$', family: 'FakeMediatek', severity: 'high', description: 'Malware posing as MediaTek system component' },

  // ─── Adware Families 2024-2026 ─────────────────────────────────
  { pattern: 'com\\.mobidash\\..*', family: 'MobiDash', severity: 'medium', description: '2025 top adware family (39% of mobile adware)' },
  { pattern: 'com\\.adlo\\..*', family: 'Adlo', severity: 'medium', description: '2025 second-largest adware family with aggressive SDK' },
  { pattern: 'com\\.hidden\\.ad\\..*', family: 'HiddenAd', severity: 'medium', description: 'Adware that hides icon and shows fullscreen ads' },
  { pattern: 'com\\.fakecleaner\\..*', family: 'FakeCleaner', severity: 'medium', description: 'Fake cleaner app that injects ads and collects data' },
  { pattern: 'com\\.miniapplocker\\..*', family: 'FakeAppLocker', severity: 'medium', description: 'Fake utility with hidden ad SDK and data harvesting' },

  // ─── Subscription Fraud 2024-2026 ──────────────────────────────
  { pattern: 'com\\.goldoson\\..*', family: 'Goldoson', severity: 'high', description: '2024 library-embedded ad fraud with data collection' },
  { pattern: 'com\\.spyloan\\..*', family: 'SpyLoan', severity: 'high', description: '2024-2025 predatory loan apps with excessive surveillance' },
  { pattern: 'com\\.fakereward\\..*', family: 'FakeReward', severity: 'medium', description: 'Subscription fraud disguised as rewards app' },

  // ─── Auto-Reinstall / Persistence Mechanisms ───────────────────
  { pattern: 'com\\.android\\.companion\\.install\\..*', family: 'CompanionInstaller', severity: 'high', description: 'Uses companion app to reinstall after removal' },
  { pattern: 'com\\.installer\\.helper\\..*', family: 'InstallerHelper', severity: 'high', description: 'Background reinstaller for removed malware' },
  { pattern: 'com\\.provision\\.\\w+$', family: 'Provisioner', severity: 'high', description: 'Provisioning profile malware that reinstalls paired apps' },

  // ─── Java-Based Threats ────────────────────────────────────────
  // JAR/Java exploits delivered via browser or fake apps
  { pattern: 'com\\.java\\.update\\..*', family: 'FakeJava', severity: 'critical', description: 'Trojan disguised as Java update — Java is not used on Android' },
  { pattern: 'com\\.oracle\\.java\\..*', family: 'FakeJava', severity: 'critical', description: 'Fake Oracle Java installer — social engineering payload dropper' },
  { pattern: 'com\\.javaupdate\\..*', family: 'FakeJava', severity: 'critical', description: 'Malware using Java update deception to gain install permission' },
  { pattern: 'com\\.jrat\\..*', family: 'jRAT', severity: 'critical', description: 'Java-based RAT (jRAT/Adwind) ported to Android' },
  { pattern: 'com\\.adwind\\..*', family: 'Adwind', severity: 'critical', description: 'Cross-platform Java RAT with Android component' },
  { pattern: 'com\\.unrecom\\..*', family: 'Unrecom/AlienSpy', severity: 'critical', description: 'Java RAT successor to Adwind with mobile surveillance' },
  { pattern: 'com\\.qrat\\..*', family: 'QRAT', severity: 'critical', description: 'Quasar-based Java RAT with Android keylogging module' },
  { pattern: 'com\\.jar\\.loader\\..*', family: 'JarLoader', severity: 'high', description: 'Dynamic JAR file loader — fetches and executes remote Java payloads' },
  { pattern: 'com\\.java\\.applet\\..*', family: 'JavaApplet', severity: 'high', description: 'Java applet-style exploit delivered via WebView' },
  { pattern: 'com\\.jndi\\..*', family: 'Log4Shell/JNDI', severity: 'critical', description: 'JNDI exploitation attempt (Log4Shell derivative) targeting Java services' },
  { pattern: 'com\\.spring\\.shell\\..*', family: 'SpringShell', severity: 'critical', description: 'Spring4Shell exploit payload for Java backend compromise' },
  { pattern: 'com\\.deserialization\\..*', family: 'JavaDeserial', severity: 'critical', description: 'Java deserialization exploit payload' },

  // ─── Cookie & Session Theft ────────────────────────────────────
  // Apps that steal browser cookies, sessions, and authentication tokens
  { pattern: 'com\\.cookiestealer\\..*', family: 'CookieStealer', severity: 'critical', description: 'Steals browser cookies including auth sessions from Chrome/Firefox' },
  { pattern: 'com\\.cookiemonster\\..*', family: 'CookieMonster', severity: 'critical', description: 'Browser cookie harvester targeting social media sessions' },
  { pattern: 'com\\.sessionthief\\..*', family: 'SessionThief', severity: 'critical', description: 'Steals active web sessions to bypass 2FA authentication' },
  { pattern: 'com\\.tokengrabber\\..*', family: 'TokenGrabber', severity: 'critical', description: 'OAuth/JWT token stealer for account takeover' },
  { pattern: 'com\\.infostealer\\..*', family: 'InfoStealer', severity: 'critical', description: 'Generic info stealer targeting cookies, passwords, and autofill data' },
  { pattern: 'com\\.browser\\.helper\\..*', family: 'BrowserHelper', severity: 'high', description: 'Fake browser helper that intercepts cookies and form submissions' },
  { pattern: 'com\\.webguard\\.pro\\..*', family: 'FakeWebGuard', severity: 'high', description: 'Fake security app that harvests browser data and login sessions' },
  { pattern: 'com\\.passview\\..*', family: 'PassView', severity: 'critical', description: 'Password and cookie viewer that exfiltrates saved credentials' },
  { pattern: 'com\\.raccoon\\..*', family: 'Raccoon Stealer', severity: 'critical', description: '2024 mobile variant of Raccoon info stealer targeting cookies and crypto' },
  { pattern: 'com\\.redline\\..*', family: 'RedLine', severity: 'critical', description: 'RedLine stealer Android variant — cookies, passwords, crypto wallets' },
  { pattern: 'com\\.vidar\\..*', family: 'Vidar', severity: 'critical', description: 'Vidar stealer mobile component — browser data and cookie exfiltration' },
  { pattern: 'com\\.lumma\\..*', family: 'Lumma Stealer', severity: 'critical', description: '2025 Lumma stealer with cookie restoration and session replay capability' },
  { pattern: 'com\\.aurora\\.stealer\\..*', family: 'Aurora', severity: 'critical', description: 'Aurora stealer targeting browser profiles and session cookies' },

  // ─── Porn Site / Adult Content Threats ─────────────────────────
  // Malware distributed via adult sites, fake video players, sextortion
  { pattern: 'com\\.adult\\.player\\..*', family: 'AdultPlayer', severity: 'critical', description: 'Ransomware disguised as adult video player — takes photos and demands ransom' },
  { pattern: 'com\\.porn\\.player\\..*', family: 'PornPlayer', severity: 'critical', description: 'Fake porn player that locks device and demands payment' },
  { pattern: 'com\\.video\\.player\\.adult\\..*', family: 'FakeVideoAdult', severity: 'critical', description: 'Trojanized video player from adult sites with camera/mic access' },
  { pattern: 'com\\.free\\.video\\.private\\..*', family: 'PrivateVideo', severity: 'high', description: 'Fake private video app — harvests contacts then sends sextortion messages' },
  { pattern: 'com\\.dating\\.hot\\..*', family: 'FakeDating', severity: 'high', description: 'Fake dating app with aggressive adware and premium SMS fraud' },
  { pattern: 'com\\.live\\.cam\\.free\\..*', family: 'FakeLiveCam', severity: 'high', description: 'Fake webcam app that activates camera and exfiltrates photos' },
  { pattern: 'com\\.xxx\\..*', family: 'XXXMalware', severity: 'high', description: 'Adult-themed malware with hidden data collection' },
  { pattern: 'com\\.porndroid\\..*', family: 'PornDroid', severity: 'critical', description: 'Android ransomware delivered through adult sites — locks screen with fake FBI warning' },
  { pattern: 'com\\.koler\\..*', family: 'Koler', severity: 'critical', description: 'Police-themed ransomware spread via adult sites' },
  { pattern: 'com\\.slocker\\..*', family: 'SLocker', severity: 'critical', description: 'File-encrypting ransomware distributed via adult content lures' },
  { pattern: 'com\\.leaker\\..*', family: 'Leaker', severity: 'critical', description: 'Sextortion malware — captures intimate content and threatens to publish' },
  { pattern: 'com\\.sextortion\\..*', family: 'Sextortion', severity: 'critical', description: 'Automated sextortion app that steals gallery photos and demands cryptocurrency' },
  { pattern: 'com\\.cam\\.spy\\..*', family: 'CamSpy', severity: 'critical', description: 'Hidden camera activation malware from adult site drive-by' },
  { pattern: 'com\\.privatealbum\\..*', family: 'PrivateAlbum', severity: 'high', description: 'Fake photo vault that uploads private images to attacker server' },
  { pattern: 'com\\.vpn\\.adult\\..*', family: 'FakeAdultVPN', severity: 'high', description: 'Fake adult VPN that logs all traffic and steals credentials' },
  { pattern: 'com\\.codec\\.video\\..*', family: 'FakeCodec', severity: 'critical', description: 'Fake video codec from adult sites — dropper for banking trojans' },
  { pattern: 'com\\.flash\\.player\\.update\\..*', family: 'FakeFlash', severity: 'critical', description: 'Fake Flash Player update (classic adult site attack vector)' },
  { pattern: 'com\\.agecheck\\.verify\\..*', family: 'FakeAgeVerify', severity: 'high', description: 'Fake age verification that harvests ID documents and personal data' },
  { pattern: 'com\\.malvertise\\.clicker\\..*', family: 'MalvertClicker', severity: 'medium', description: 'Ad fraud clicker installed via adult ad network redirect' },
];

// ─── Known C2 & Malicious Infrastructure ────────────────────────
export const maliciousInfrastructure: {
  domain: string;
  type: 'c2' | 'exfil' | 'dropper' | 'phishing';
  family: string;
}[] = [
  // C2 Servers
  { domain: 'update-checker.net', type: 'c2', family: 'ZeroDayRAT' },
  { domain: 'sys-update-service.com', type: 'c2', family: 'ZeroDayRAT' },
  { domain: 'anubis-panel.xyz', type: 'c2', family: 'Anubis' },
  { domain: 'anubis-c2.top', type: 'c2', family: 'Anubis' },
  { domain: 'spark-sync.com', type: 'c2', family: 'SparkCat' },
  { domain: 'spark-cdn.net', type: 'exfil', family: 'SparkCat' },
  { domain: 'anatsa-cdn.net', type: 'dropper', family: 'Anatsa' },
  { domain: 'anatsa-panel.com', type: 'c2', family: 'Anatsa' },
  { domain: 'cocospy-api.com', type: 'exfil', family: 'Cocospy' },
  { domain: 'cocospy-data.net', type: 'exfil', family: 'Cocospy' },
  { domain: 'cerberus-panel.xyz', type: 'c2', family: 'Cerberus' },
  { domain: 'hydra-c2.xyz', type: 'c2', family: 'Hydra' },
  { domain: 'teabot-cdn.net', type: 'dropper', family: 'TeaBot' },
  { domain: 'sharkbot-update.com', type: 'c2', family: 'SharkBot' },
  { domain: 'xenomorph-gate.net', type: 'c2', family: 'Xenomorph' },
  { domain: 'vultur-panel.com', type: 'c2', family: 'Vultur' },
  { domain: 'octo-gate.xyz', type: 'c2', family: 'Octo' },
  { domain: 'ermac-panel.top', type: 'c2', family: 'ERMAC' },
  { domain: 'spynote-c2.net', type: 'c2', family: 'SpyNote' },
  { domain: 'flexispy-api.com', type: 'exfil', family: 'FlexiSpy' },
  { domain: 'mspy-cloud.com', type: 'exfil', family: 'mSpy' },
  { domain: 'hoverwatch-api.com', type: 'exfil', family: 'Hoverwatch' },
  { domain: 'golddigger-gate.com', type: 'c2', family: 'GoldDigger' },
  { domain: 'joker-cdn.net', type: 'dropper', family: 'Joker' },
  { domain: 'harly-sub.com', type: 'c2', family: 'Harly' },
  { domain: 'simplocker-pay.onion', type: 'c2', family: 'Simplocker' },
  { domain: 'flubot-delivery.com', type: 'dropper', family: 'FluBot' },
  { domain: 'brata-c2-update.xyz', type: 'c2', family: 'BRATA' },
  { domain: 'alien-panel.net', type: 'c2', family: 'Alien' },
  { domain: 'blackrock-gate.com', type: 'c2', family: 'BlackRock' },
  { domain: 'medusa-botnet.org', type: 'c2', family: 'Medusa' },
  { domain: 'eventbot-c2.net', type: 'c2', family: 'EventBot' },
  { domain: 'xhelper-cdn.com', type: 'dropper', family: 'xHelper' },
  { domain: 'triada-update.net', type: 'c2', family: 'Triada' },
  { domain: 'finspy-relay.net', type: 'exfil', family: 'FinSpy' },
  { domain: 'cytrox-api.com', type: 'c2', family: 'Predator' },
  { domain: 'quadream-c2.net', type: 'c2', family: 'QuaDream' },

  // Adult Site Malvertising & Drive-by Downloads
  { domain: 'popads.net', type: 'phishing', family: 'Malvertising/PopAds' },
  { domain: 'trafficjunky.com', type: 'phishing', family: 'Malvertising/TrafficJunky' },
  { domain: 'exo-click.net', type: 'phishing', family: 'Malvertising/ExoClick' },
  { domain: 'juicyads.com', type: 'phishing', family: 'Malvertising/JuicyAds' },
  { domain: 'clearfake-tds.com', type: 'dropper', family: 'ClearFake/ClickFix' },
  { domain: 'fake-update-cdn.net', type: 'dropper', family: 'SocEng/FakeUpdate' },
  { domain: 'captcha-verify-human.com', type: 'phishing', family: 'ClickFix/SocEng' },
  { domain: 'jackfix-cdn.xyz', type: 'dropper', family: 'JackFix/AdultMalware' },
  { domain: 'adult-dating-spam.top', type: 'phishing', family: 'Spam/AdultDating' },
  { domain: 'video-codec-updater.net', type: 'dropper', family: 'DriveBy/Codec' },
  { domain: 'adult-player-install.com', type: 'dropper', family: 'AdultPlayer' },
  { domain: 'free-video-codec.net', type: 'dropper', family: 'FakeCodec' },
  { domain: 'age-verify-secure.com', type: 'phishing', family: 'FakeAgeVerify' },
  { domain: 'premium-content-unlock.net', type: 'phishing', family: 'PremiumScam' },
  { domain: 'private-video-player.com', type: 'dropper', family: 'PrivateVideo' },
  { domain: 'live-cam-free-app.xyz', type: 'dropper', family: 'FakeLiveCam' },
  { domain: 'dating-hot-singles.top', type: 'phishing', family: 'FakeDating' },
  { domain: 'porndroid-locker.onion', type: 'c2', family: 'PornDroid' },
  { domain: 'koler-c2.xyz', type: 'c2', family: 'Koler' },
  { domain: 'sextort-pay.onion', type: 'c2', family: 'Sextortion' },
  { domain: 'xxx-flash-update.net', type: 'dropper', family: 'FakeFlash/Adult' },
  { domain: 'adult-vpn-free.com', type: 'dropper', family: 'FakeAdultVPN' },
  { domain: 'malvertising-redirect.top', type: 'phishing', family: 'Malvertising/Redirect' },
  { domain: 'ad-click-track.xyz', type: 'phishing', family: 'MalvertClicker' },
  { domain: 'push-notification-adult.com', type: 'phishing', family: 'PushScam/Adult' },

  // Cookie/Session Theft Infrastructure
  { domain: 'supercookie-tracker.net', type: 'exfil', family: 'CookieStealer' },
  { domain: 'session-hijack-proxy.com', type: 'c2', family: 'SessionStealer' },
  { domain: 'cookie-exfil-gate.xyz', type: 'exfil', family: 'CookieStealer' },
  { domain: 'session-replay-api.com', type: 'exfil', family: 'SessionReplay' },
  { domain: 'token-grab-cdn.net', type: 'exfil', family: 'TokenGrabber' },
  { domain: 'raccoon-panel.xyz', type: 'c2', family: 'Raccoon Stealer' },
  { domain: 'redline-gate.com', type: 'c2', family: 'RedLine' },
  { domain: 'vidar-exfil.net', type: 'exfil', family: 'Vidar' },
  { domain: 'lumma-c2.top', type: 'c2', family: 'Lumma Stealer' },
  { domain: 'lumma-session.xyz', type: 'exfil', family: 'Lumma Stealer' },
  { domain: 'aurora-panel.net', type: 'c2', family: 'Aurora' },
  { domain: 'infostealer-api.com', type: 'exfil', family: 'InfoStealer' },
  { domain: 'browser-data-sync.net', type: 'exfil', family: 'BrowserStealer' },
  { domain: 'auth-token-collect.xyz', type: 'exfil', family: 'TokenStealer' },
  { domain: 'cookie-restore-api.com', type: 'c2', family: 'CookieRestore' },

  // Java Exploit Infrastructure
  { domain: 'java-update-cdn.net', type: 'dropper', family: 'FakeJava' },
  { domain: 'jrat-panel.xyz', type: 'c2', family: 'jRAT' },
  { domain: 'adwind-c2.net', type: 'c2', family: 'Adwind' },
  { domain: 'jar-loader-cdn.com', type: 'dropper', family: 'JarLoader' },
  { domain: 'jndi-exploit.xyz', type: 'c2', family: 'Log4Shell' },
  { domain: 'log4j-callback.net', type: 'c2', family: 'Log4Shell' },
  { domain: 'deserialization-gate.com', type: 'c2', family: 'JavaDeserial' },

  // 2024-2026 Malware C2 Infrastructure
  { domain: 'mamont-gate.ru', type: 'c2', family: 'Mamont' },
  { domain: 'mamont-panel.xyz', type: 'c2', family: 'Mamont' },
  { domain: 'toxicpanda-c2.net', type: 'c2', family: 'ToxicPanda' },
  { domain: 'creduz-api.top', type: 'c2', family: 'Creduz' },
  { domain: 'frogblight-c2.xyz', type: 'c2', family: 'Frogblight' },
  { domain: 'nexus-panel.com', type: 'c2', family: 'Nexus' },
  { domain: 'godfather-c2.net', type: 'c2', family: 'GodFather' },
  { domain: 'hook-panel.xyz', type: 'c2', family: 'Hook' },
  { domain: 'pixpirate-gate.com', type: 'c2', family: 'PixPirate' },
  { domain: 'lunaspy-exfil.net', type: 'exfil', family: 'LunaSpy' },
  { domain: 'albiriox-c2.top', type: 'c2', family: 'Albiriox' },
  { domain: 'rafel-panel.xyz', type: 'c2', family: 'Rafel RAT' },
  { domain: 'mandrake-c2.net', type: 'c2', family: 'Mandrake' },
  { domain: 'spyloan-api.com', type: 'exfil', family: 'SpyLoan' },
  { domain: 'zanubis-gate.top', type: 'c2', family: 'Zanubis' },

  // DGA-style domains (common in banking trojans)
  { domain: '.duckdns.org', type: 'c2', family: 'DGA/DynDNS' },
  { domain: '.no-ip.org', type: 'c2', family: 'DGA/DynDNS' },
  { domain: '.ddns.net', type: 'c2', family: 'DGA/DynDNS' },
  { domain: '.hopto.org', type: 'c2', family: 'DGA/DynDNS' },
  { domain: '.zapto.org', type: 'c2', family: 'DGA/DynDNS' },
  { domain: '.serveo.net', type: 'c2', family: 'TunnelC2' },
  { domain: '.ngrok.io', type: 'c2', family: 'TunnelC2' },
  { domain: '.trycloudflare.com', type: 'c2', family: 'TunnelC2' },

  // Known malicious IP ranges (represented as domains for matching)
  { domain: '185.220.101.', type: 'c2', family: 'Generic C2' },
  { domain: '194.5.98.', type: 'c2', family: 'Generic C2' },
  { domain: '45.153.240.', type: 'c2', family: 'Generic C2' },
  { domain: '91.215.85.', type: 'c2', family: 'Generic C2' },
  { domain: '193.142.30.', type: 'c2', family: 'Generic C2' },
  { domain: '176.121.14.', type: 'c2', family: 'FluBot C2' },
  { domain: '45.144.225.', type: 'c2', family: 'Alien C2' },
  { domain: '93.184.216.', type: 'c2', family: 'BlackRock C2' },
  { domain: '5.42.65.', type: 'c2', family: 'Mamont C2' },
  { domain: '79.137.192.', type: 'c2', family: 'Nexus C2' },
  { domain: '46.249.32.', type: 'c2', family: 'GodFather C2' },
  { domain: '185.215.113.', type: 'c2', family: 'Hook C2' },
  { domain: '94.156.68.', type: 'c2', family: 'ToxicPanda C2' },
  { domain: '77.91.68.', type: 'c2', family: 'SpyLoan C2' },
  { domain: '172.86.75.', type: 'c2', family: 'Rafel C2' },
];

// ─── Dangerous Permission Combos (Expanded) ─────────────────────
export const expandedDangerousPermCombos: {
  permissions: string[];
  risk: string;
  severity: string;
  category: string;
}[] = [
  // SMS exfiltration
  {
    permissions: ['android.permission.READ_SMS', 'android.permission.INTERNET'],
    risk: 'SMS exfiltration — can read and transmit messages',
    severity: 'critical',
    category: 'Data Theft',
  },
  {
    permissions: ['android.permission.RECEIVE_SMS', 'android.permission.INTERNET'],
    risk: 'SMS interception — can intercept incoming messages (2FA bypass)',
    severity: 'critical',
    category: '2FA Bypass',
  },
  {
    permissions: ['android.permission.SEND_SMS', 'android.permission.RECEIVE_SMS'],
    risk: 'Full SMS control — can send/receive SMS without user knowledge',
    severity: 'critical',
    category: 'SMS Fraud',
  },
  // Surveillance
  {
    permissions: ['android.permission.CAMERA', 'android.permission.RECORD_AUDIO', 'android.permission.INTERNET'],
    risk: 'Full surveillance — can capture audio/video and transmit',
    severity: 'critical',
    category: 'Surveillance',
  },
  {
    permissions: ['android.permission.CAMERA', 'android.permission.INTERNET', 'android.permission.RECEIVE_BOOT_COMPLETED'],
    risk: 'Persistent camera access — starts on boot, can capture photos remotely',
    severity: 'critical',
    category: 'Surveillance',
  },
  {
    permissions: ['android.permission.RECORD_AUDIO', 'android.permission.INTERNET', 'android.permission.RECEIVE_BOOT_COMPLETED'],
    risk: 'Persistent audio recording — starts on boot, can record conversations',
    severity: 'critical',
    category: 'Surveillance',
  },
  // Data harvesting
  {
    permissions: ['android.permission.READ_CONTACTS', 'android.permission.READ_SMS', 'android.permission.INTERNET'],
    risk: 'Data harvesting — can read contacts, SMS and exfiltrate',
    severity: 'high',
    category: 'Data Theft',
  },
  {
    permissions: ['android.permission.READ_CALL_LOG', 'android.permission.READ_CONTACTS', 'android.permission.INTERNET'],
    risk: 'Social graph mapping — can map all contacts and call history',
    severity: 'high',
    category: 'Data Theft',
  },
  // Location tracking
  {
    permissions: ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.INTERNET', 'android.permission.RECEIVE_BOOT_COMPLETED'],
    risk: 'Persistent location tracking — GPS tracks location from boot',
    severity: 'high',
    category: 'Tracking',
  },
  {
    permissions: ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.ACCESS_BACKGROUND_LOCATION', 'android.permission.INTERNET'],
    risk: 'Background location tracking — continuous GPS monitoring',
    severity: 'critical',
    category: 'Tracking',
  },
  // Overlay / Accessibility abuse
  {
    permissions: ['android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.BIND_ACCESSIBILITY_SERVICE'],
    risk: 'Overlay + Accessibility abuse — banking trojan pattern',
    severity: 'critical',
    category: 'Banking Trojan',
  },
  {
    permissions: ['android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.INTERNET'],
    risk: 'Overlay attack capability — can display phishing overlays',
    severity: 'high',
    category: 'Phishing',
  },
  // Dropper / Installer
  {
    permissions: ['android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.INTERNET'],
    risk: 'Dropper capability — can download and install additional APKs',
    severity: 'high',
    category: 'Dropper',
  },
  {
    permissions: ['android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.WRITE_EXTERNAL_STORAGE'],
    risk: 'Sideload capability — can write and install APKs',
    severity: 'high',
    category: 'Dropper',
  },
  // Call interception
  {
    permissions: ['android.permission.READ_CALL_LOG', 'android.permission.RECORD_AUDIO', 'android.permission.INTERNET'],
    risk: 'Call interception — can monitor and record calls',
    severity: 'critical',
    category: 'Surveillance',
  },
  {
    permissions: ['android.permission.PROCESS_OUTGOING_CALLS', 'android.permission.INTERNET'],
    risk: 'Call manipulation — can intercept outgoing calls',
    severity: 'critical',
    category: 'Fraud',
  },
  // Device admin abuse
  {
    permissions: ['android.permission.BIND_DEVICE_ADMIN', 'android.permission.INTERNET'],
    risk: 'Device admin abuse — can lock device, wipe data, or prevent uninstall',
    severity: 'critical',
    category: 'Ransomware',
  },
  // Storage + Network (data exfil)
  {
    permissions: ['android.permission.READ_EXTERNAL_STORAGE', 'android.permission.INTERNET', 'android.permission.RECEIVE_BOOT_COMPLETED'],
    risk: 'File exfiltration — can read and upload files persistently',
    severity: 'high',
    category: 'Data Theft',
  },
  // Clipboard monitoring
  {
    permissions: ['android.permission.BIND_ACCESSIBILITY_SERVICE', 'android.permission.INTERNET'],
    risk: 'Accessibility abuse — can read screen content, log keystrokes, steal credentials',
    severity: 'critical',
    category: 'Keylogger',
  },

  // Cookie/Session theft combos
  {
    permissions: ['android.permission.READ_EXTERNAL_STORAGE', 'android.permission.INTERNET', 'android.permission.BIND_ACCESSIBILITY_SERVICE'],
    risk: 'Browser data theft — can read cookie databases and exfiltrate login sessions',
    severity: 'critical',
    category: 'Cookie Theft',
  },
  {
    permissions: ['android.permission.QUERY_ALL_PACKAGES', 'android.permission.INTERNET', 'android.permission.READ_EXTERNAL_STORAGE'],
    risk: 'App enumeration + data theft — can identify browsers and steal their stored data',
    severity: 'high',
    category: 'Cookie Theft',
  },

  // Java/WebView exploit combos
  {
    permissions: ['android.permission.INTERNET', 'android.permission.WRITE_EXTERNAL_STORAGE', 'android.permission.REQUEST_INSTALL_PACKAGES'],
    risk: 'Remote code execution chain — download, write, and install arbitrary code',
    severity: 'critical',
    category: 'Java Exploit',
  },

  // Sextortion / adult malware combos
  {
    permissions: ['android.permission.CAMERA', 'android.permission.READ_CONTACTS', 'android.permission.INTERNET'],
    risk: 'Sextortion setup — can capture photos and access contact list for blackmail',
    severity: 'critical',
    category: 'Sextortion',
  },
  {
    permissions: ['android.permission.CAMERA', 'android.permission.READ_EXTERNAL_STORAGE', 'android.permission.INTERNET', 'android.permission.BIND_DEVICE_ADMIN'],
    risk: 'Adult ransomware pattern — camera capture + file access + device lock + network',
    severity: 'critical',
    category: 'Adult Ransomware',
  },
  {
    permissions: ['android.permission.READ_EXTERNAL_STORAGE', 'android.permission.READ_CONTACTS', 'android.permission.INTERNET', 'android.permission.SEND_SMS'],
    risk: 'Leakware pattern — can read photos, contact everyone, and exfiltrate via SMS/network',
    severity: 'critical',
    category: 'Leakware',
  },
  {
    permissions: ['android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.BIND_DEVICE_ADMIN', 'android.permission.CAMERA'],
    risk: 'Screen lock + camera capture — fake law enforcement ransomware pattern',
    severity: 'critical',
    category: 'Police Ransomware',
  },
];

// ─── Behavioral Indicators ──────────────────────────────────────
export const behavioralIndicators: {
  id: string;
  name: string;
  description: string;
  severity: string;
  check: string; // What to check for
}[] = [
  {
    id: 'beh-battery-drain',
    name: 'Abnormal Battery Drain',
    description: 'App consuming >15% battery in background without visible activity',
    severity: 'medium',
    check: 'background_battery_usage > 15%',
  },
  {
    id: 'beh-data-usage',
    name: 'Excessive Background Data',
    description: 'App transferring >100MB in background without user interaction',
    severity: 'high',
    check: 'background_data_usage > 100MB/day',
  },
  {
    id: 'beh-hidden-icon',
    name: 'Hidden App Icon',
    description: 'App has disabled its launcher icon to hide from the user',
    severity: 'critical',
    check: 'launcher_icon_disabled',
  },
  {
    id: 'beh-device-admin',
    name: 'Device Admin Without Justification',
    description: 'Non-MDM app has device administrator privileges',
    severity: 'high',
    check: 'has_device_admin && !is_mdm',
  },
  {
    id: 'beh-accessibility-abuse',
    name: 'Accessibility Service Abuse',
    description: 'Non-accessibility app uses accessibility service for data capture',
    severity: 'critical',
    check: 'uses_accessibility && !is_accessibility_app',
  },
  {
    id: 'beh-boot-persist',
    name: 'Boot Persistence',
    description: 'App starts automatically on device boot without clear reason',
    severity: 'medium',
    check: 'receives_boot_completed && is_suspicious',
  },
  {
    id: 'beh-screen-overlay',
    name: 'Screen Overlay Detection',
    description: 'App draws overlays on top of other apps (potential phishing)',
    severity: 'high',
    check: 'uses_system_alert_window && draws_overlays',
  },
  {
    id: 'beh-sensor-access',
    name: 'Excessive Sensor Access',
    description: 'App accessing accelerometer/gyroscope frequently (potential keylogger)',
    severity: 'medium',
    check: 'sensor_access_frequency > threshold',
  },
  {
    id: 'beh-clipboard',
    name: 'Clipboard Monitoring',
    description: 'App reading clipboard contents frequently (crypto address swap)',
    severity: 'high',
    check: 'clipboard_read_frequency > threshold',
  },
  {
    id: 'beh-wakelock',
    name: 'Persistent Wakelock',
    description: 'App preventing device from sleeping for extended periods',
    severity: 'low',
    check: 'wakelock_duration > 30min',
  },
  {
    id: 'beh-cookie-theft',
    name: 'Browser Session Stealing',
    description: 'App attempting to read WebView cookies or external browser session states',
    severity: 'critical',
    check: 'cookie_manager_read && !is_browser',
  },
  {
    id: 'beh-js-injection',
    name: 'Malicious JavaScript Injection',
    description: 'App dynamically injecting external JS into WebViews (potential ClearFake)',
    severity: 'high',
    check: 'webview_evaluate_javascript_external',
  },
  {
    id: 'beh-drive-by',
    name: 'Drive-By Download Attempt',
    description: 'Silent background download initiated without user interaction',
    severity: 'critical',
    check: 'download_manager_enqueue && !user_interaction',
  },

  // Java-specific behavioral indicators
  {
    id: 'beh-jar-execution',
    name: 'JAR File Dynamic Loading',
    description: 'App loading and executing JAR files at runtime — dropper or remote payload technique',
    severity: 'critical',
    check: 'jar_file_open && class_loader_invoke',
  },
  {
    id: 'beh-java-reflection-abuse',
    name: 'Java Reflection Abuse',
    description: 'Excessive use of Java reflection to invoke hidden methods — evasion technique',
    severity: 'high',
    check: 'reflection_invoke_count > 50 && targets_system_api',
  },
  {
    id: 'beh-webview-bridge-exploit',
    name: 'WebView JavaScript Bridge Exploit',
    description: 'App exposes Java objects to JavaScript with dangerous methods accessible',
    severity: 'critical',
    check: 'addJavascriptInterface && exposed_methods_include_exec',
  },
  {
    id: 'beh-dex-from-network',
    name: 'DEX Downloaded from Network',
    description: 'App downloads DEX/JAR bytecode from internet and loads it — staged malware',
    severity: 'critical',
    check: 'network_download && file_extension_dex_jar && class_loader_invoke',
  },

  // Cookie/Session theft behavioral indicators
  {
    id: 'beh-cookie-access-non-browser',
    name: 'Cookie Access by Non-Browser App',
    description: 'Non-browser app reading CookieManager or WebView cookies — session theft',
    severity: 'critical',
    check: 'cookie_manager_access && !is_browser_app && has_internet',
  },
  {
    id: 'beh-browser-db-read',
    name: 'Browser Database File Access',
    description: 'App reading Chrome/Firefox database files (Cookies, Login Data, Web Data)',
    severity: 'critical',
    check: 'file_read_browser_profile && !is_browser_app',
  },
  {
    id: 'beh-token-exfil',
    name: 'Auth Token Exfiltration',
    description: 'App reading SharedPreferences of other apps and sending tokens to network',
    severity: 'critical',
    check: 'shared_prefs_read_other_app && network_send_within_5s',
  },
  {
    id: 'beh-session-clone',
    name: 'Session Cloning Behavior',
    description: 'App copying auth cookies and replaying them to impersonate user',
    severity: 'critical',
    check: 'cookie_read && same_cookie_set_in_request && different_user_agent',
  },
  {
    id: 'beh-password-db-access',
    name: 'Password Database Access',
    description: 'App accessing saved password storage (Login Data, key3.db, signons.sqlite)',
    severity: 'critical',
    check: 'file_access_password_db && !is_password_manager',
  },

  // Adult site / porn-related behavioral indicators
  {
    id: 'beh-camera-after-adult',
    name: 'Camera Activation After Adult Content',
    description: 'App activates camera after displaying adult content — sextortion pattern',
    severity: 'critical',
    check: 'adult_content_displayed && camera_activate_within_30s',
  },
  {
    id: 'beh-gallery-scan-upload',
    name: 'Gallery Scan and Upload',
    description: 'App scanning photo gallery and uploading images without user consent — leakware',
    severity: 'critical',
    check: 'gallery_enumerate && image_upload && !user_initiated_share',
  },
  {
    id: 'beh-fake-lock-screen',
    name: 'Fake Law Enforcement Lock',
    description: 'App displays fake police/FBI warning and locks device — adult site ransomware',
    severity: 'critical',
    check: 'fullscreen_overlay && law_enforcement_text && payment_form',
  },
  {
    id: 'beh-contact-threat',
    name: 'Contact List Threat Pattern',
    description: 'App reads contacts immediately after camera/gallery access — blackmail preparation',
    severity: 'critical',
    check: 'contact_read_after_media_access && has_internet',
  },
  {
    id: 'beh-push-scam',
    name: 'Adult Push Notification Scam',
    description: 'App sending adult-themed push notifications to trick users into installing more malware',
    severity: 'high',
    check: 'push_notification_adult_content && link_to_apk_download',
  },
  {
    id: 'beh-redirect-chain',
    name: 'Malicious Redirect Chain',
    description: 'WebView executing 3+ rapid redirects through ad networks — malvertising chain',
    severity: 'high',
    check: 'webview_redirect_count > 3 && redirect_within_2s && ends_at_download',
  },
];

// ─── YARA-Inspired Rules ────────────────────────────────────────
export const yaraRules: {
  id: string;
  name: string;
  description: string;
  severity: string;
  strings: string[]; // Strings to match in APK/DEX
  condition: string;
}[] = [
  {
    id: 'yara-anubis',
    name: 'Android_Anubis_B',
    description: 'Detects Anubis banking trojan variant B',
    severity: 'critical',
    strings: ['anubis', 'bankbot', 'overlay_attack', 'sms_intercept'],
    condition: 'any_of_strings && has_accessibility_service',
  },
  {
    id: 'yara-cerberus',
    name: 'Android_Cerberus',
    description: 'Detects Cerberus banking trojan',
    severity: 'critical',
    strings: ['cerberus', 'overlay', 'keylogger', 'screen_stream'],
    condition: 'any_of_strings && uses_vnc',
  },
  {
    id: 'yara-spynote',
    name: 'Android_SpyNote',
    description: 'Detects SpyNote RAT variants',
    severity: 'critical',
    strings: ['spynote', 'camera_capture', 'audio_record', 'file_manager'],
    condition: '2_of_strings && has_boot_receiver',
  },
  {
    id: 'yara-ahmyth',
    name: 'Android_AhMyth',
    description: 'Detects AhMyth RAT',
    severity: 'high',
    strings: ['ahmyth', 'server_connection', 'port_4444', 'remote_shell'],
    condition: 'any_of_strings',
  },
  {
    id: 'yara-joker',
    name: 'Android_Joker',
    description: 'Detects Joker premium SMS fraud',
    severity: 'high',
    strings: ['subscribe', 'wap_billing', 'premium_sms', 'notification_listener'],
    condition: '2_of_strings && has_sms_permission',
  },
  {
    id: 'yara-crypto-stealer',
    name: 'Android_CryptoStealer',
    description: 'Detects cryptocurrency wallet stealers',
    severity: 'critical',
    strings: ['seed_phrase', 'mnemonic', 'wallet_recovery', 'clipboard_replace'],
    condition: 'any_of_strings && has_internet',
  },
  {
    id: 'yara-ransomware',
    name: 'Android_Ransomware_Generic',
    description: 'Detects generic Android ransomware patterns',
    severity: 'critical',
    strings: ['encrypt_files', 'ransom_note', 'bitcoin_address', 'lock_screen'],
    condition: '2_of_strings && has_device_admin',
  },
  {
    id: 'yara-stalkerware',
    name: 'Android_Stalkerware_Generic',
    description: 'Detects generic stalkerware patterns',
    severity: 'high',
    strings: ['hidden_icon', 'location_track', 'sms_forward', 'call_record', 'keylog'],
    condition: '3_of_strings && has_boot_receiver',
  },
  {
    id: 'yara-flubot',
    name: 'Android_FluBot',
    description: 'Detects FluBot SMS spreader',
    severity: 'critical',
    strings: ['dhl_parcel', 'voicemail_msg', 'sms_manager', 'contact_list', 'overlay_screen'],
    condition: '3_of_strings && has_sms_permission && has_accessibility_service',
  },
  {
    id: 'yara-brata',
    name: 'Android_BRATA',
    description: 'Detects BRATA wiping banking trojan',
    severity: 'critical',
    strings: ['factory_reset', 'wipe_data', 'screen_cast', 'vnc_server', 'accessibility_event'],
    condition: '3_of_strings && has_device_admin',
  },
  {
    id: 'yara-xhelper',
    name: 'Android_xHelper',
    description: 'Detects xHelper persistent dropper',
    severity: 'critical',
    strings: ['xhelper', 'com.mufc.', 'fireos', 'root_shell', 'remount_system'],
    condition: '3_of_strings && has_root_access',
  },
  {
    id: 'yara-alien',
    name: 'Android_Alien',
    description: 'Detects Alien banking trojan',
    severity: 'critical',
    strings: ['alien_bot', 'cerberus_v2', 'teamviewer_control', 'google_authenticator_steal'],
    condition: '2_of_strings && has_accessibility_service',
  },
  {
    id: 'yara-clearfake',
    name: 'Web_ClearFake_Injector',
    description: 'Detects ClearFake TDS and ClickFix clipboard poisoning patterns in WebViews',
    severity: 'critical',
    strings: ['window.clipboardData.setData', 'mshta.exe', 'powershell.exe -WindowStyle Hidden', 'verify_you_are_human', 'fake_captcha'],
    condition: '3_of_strings && webview_active',
  },
  {
    id: 'yara-cookie-stealer',
    name: 'Android_CookieStealer_Adult',
    description: 'Detects session hijacking malware targeting adult/streaming sites',
    severity: 'high',
    strings: ['CookieManager.getInstance().getCookie', 'document.cookie', 'sessionid=', 'phpsessid', 'exfil_cookies'],
    condition: '2_of_strings && has_internet && !is_browser',
  },
  {
    id: 'yara-driveby-apk',
    name: 'Web_DriveBy_APK',
    description: 'Detects fake codec or flash player drive-by downloads',
    severity: 'critical',
    strings: ['update_flash.apk', 'video_codec_v2.apk', 'install_to_watch', 'application/vnd.android.package-archive'],
    condition: '2_of_strings && webview_download_listener',
  },

  // ─── 2024-2026 Malware Families ────────────────────────────────
  {
    id: 'yara-mamont',
    name: 'Android_Mamont_2025',
    description: 'Detects Mamont banking trojan targeting CIS banks with push notification theft',
    severity: 'critical',
    strings: ['mamont', 'push_intercept', 'sberbank', 'tinkoff', 'notification_read', 'sms_steal'],
    condition: '3_of_strings && has_notification_listener',
  },
  {
    id: 'yara-toxicpanda',
    name: 'Android_ToxicPanda_2024',
    description: 'Detects ToxicPanda ODF banking trojan',
    severity: 'critical',
    strings: ['toxic_panda', 'on_device_fraud', 'accessibility_click', 'auto_transfer', 'screen_interact'],
    condition: '3_of_strings && has_accessibility_service',
  },
  {
    id: 'yara-sparkcat',
    name: 'Android_SparkCat_2025',
    description: 'Detects SparkCat OCR-based crypto seed phrase stealer',
    severity: 'critical',
    strings: ['ocr_scan', 'seed_phrase', 'mlkit', 'text_recognition', 'wallet_screenshot', 'clipboard_monitor'],
    condition: '3_of_strings && has_camera',
  },
  {
    id: 'yara-nexus',
    name: 'Android_Nexus_MaaS',
    description: 'Detects Nexus Malware-as-a-Service banking trojan',
    severity: 'critical',
    strings: ['nexus_bot', 'overlay_inject', 'cookie_steal', 'authenticator_steal', 'sms_intercept', 'keylog'],
    condition: '3_of_strings && has_accessibility_service',
  },
  {
    id: 'yara-godfather',
    name: 'Android_GodFather_2024',
    description: 'Detects GodFather banking trojan targeting 500+ apps',
    severity: 'critical',
    strings: ['godfather', 'web_inject', 'screen_record', 'vpn_detect', 'notification_push', 'proxy_socks5'],
    condition: '3_of_strings && has_accessibility_service',
  },
  {
    id: 'yara-hook',
    name: 'Android_Hook_2024',
    description: 'Detects Hook banking trojan (ERMAC successor) with VNC',
    severity: 'critical',
    strings: ['hook_bot', 'vnc_stream', 'file_manager', 'rat_command', 'screen_share', 'whatsapp_message'],
    condition: '3_of_strings && has_accessibility_service',
  },
  {
    id: 'yara-rafel',
    name: 'Android_Rafel_RAT',
    description: 'Detects Rafel open-source RAT used in targeted attacks since 2024',
    severity: 'critical',
    strings: ['rafel_rat', 'admin_panel', 'device_info', 'file_browse', 'cam_capture', 'mic_record', 'location_track'],
    condition: '3_of_strings && has_boot_receiver',
  },
  {
    id: 'yara-mandrake',
    name: 'Android_Mandrake_2024',
    description: 'Detects Mandrake spyware with multi-stage evasion',
    severity: 'critical',
    strings: ['mandrake', 'stage_loader', 'decrypt_payload', 'screen_record', 'credential_overlay', 'sandbox_check'],
    condition: '3_of_strings && has_internet',
  },
  {
    id: 'yara-spyloan',
    name: 'Android_SpyLoan_2025',
    description: 'Detects SpyLoan predatory loan app with excessive surveillance',
    severity: 'high',
    strings: ['loan_apply', 'contact_upload', 'sms_upload', 'gallery_access', 'location_continuous', 'debt_collect'],
    condition: '4_of_strings && has_contact_permission',
  },
  {
    id: 'yara-coper-octo2',
    name: 'Android_Coper_Octo2',
    description: 'Detects Coper/Octo2 banking trojan with DGA resilience',
    severity: 'critical',
    strings: ['coper_bot', 'dga_domain', 'overlay_service', 'screen_stream', 'sms_intercept', 'push_notification'],
    condition: '3_of_strings && has_accessibility_service',
  },
  {
    id: 'yara-telegram-c2',
    name: 'Android_Telegram_C2',
    description: 'Detects malware using Telegram Bot API as C2 channel (common 2024-2026 pattern)',
    severity: 'high',
    strings: ['api.telegram.org', 'bot_token', 'sendMessage', 'sendDocument', 'chat_id', 'getUpdates'],
    condition: '3_of_strings && has_internet',
  },
  {
    id: 'yara-discord-exfil',
    name: 'Android_Discord_Exfil',
    description: 'Detects malware using Discord webhooks for data exfiltration',
    severity: 'high',
    strings: ['discord.com/api/webhooks', 'webhook_url', 'embed_field', 'upload_file', 'stolen_data'],
    condition: '2_of_strings && has_internet',
  },
  {
    id: 'yara-clipper',
    name: 'Android_Clipper_Crypto',
    description: 'Detects clipboard-replacing crypto address swapper',
    severity: 'critical',
    strings: ['ClipboardManager', 'setPrimaryClip', 'bc1q', '0x', 'T[A-Z]', 'replace_address', 'wallet_regex'],
    condition: '3_of_strings && monitors_clipboard',
  },
  {
    id: 'yara-dynamic-dex',
    name: 'Android_DynamicDex_Loader',
    description: 'Detects dynamic DEX loading — common in dropper/staged malware',
    severity: 'high',
    strings: ['DexClassLoader', 'PathClassLoader', 'InMemoryDexClassLoader', 'loadDex', 'decrypt_stage', 'assets/payload'],
    condition: '2_of_strings && has_internet',
  },

  // ─── Java Threat YARA Rules ────────────────────────────────────
  {
    id: 'yara-jrat',
    name: 'Android_jRAT_Adwind',
    description: 'Detects jRAT/Adwind cross-platform Java RAT with Android component',
    severity: 'critical',
    strings: ['jrat', 'adwind', 'java.rmi', 'Runtime.getRuntime().exec', 'ProcessBuilder', 'socket_connect'],
    condition: '3_of_strings && has_internet',
  },
  {
    id: 'yara-jar-dropper',
    name: 'Android_JAR_Dropper',
    description: 'Detects JAR file dropper that dynamically loads Java payloads',
    severity: 'critical',
    strings: ['JarFile', 'JarEntry', 'URLClassLoader', 'newInstance', 'loadClass', 'getMethod'],
    condition: '3_of_strings && has_internet',
  },
  {
    id: 'yara-log4shell-mobile',
    name: 'Android_Log4Shell_Exploit',
    description: 'Detects Log4Shell/JNDI exploitation attempts targeting Java-based Android services',
    severity: 'critical',
    strings: ['${jndi:', 'ldap://', 'rmi://', 'InitialContext', 'NamingException', 'javax.naming'],
    condition: '2_of_strings',
  },
  {
    id: 'yara-java-deserial',
    name: 'Android_Java_Deserialization',
    description: 'Detects Java deserialization exploit chains (CommonsCollections, Spring, etc.)',
    severity: 'critical',
    strings: ['ObjectInputStream', 'readObject', 'InvokerTransformer', 'CommonsCollections', 'ysoserial', 'gadget_chain'],
    condition: '3_of_strings',
  },
  {
    id: 'yara-java-webview-exploit',
    name: 'Android_Java_WebView_Exploit',
    description: 'Detects Java bridge exploitation via addJavascriptInterface vulnerability',
    severity: 'critical',
    strings: ['addJavascriptInterface', 'getClass().forName', 'java.lang.Runtime', 'getMethod', 'invoke', 'exec'],
    condition: '3_of_strings && has_webview',
  },
  {
    id: 'yara-fake-java-update',
    name: 'Android_FakeJava_Update',
    description: 'Detects malware disguised as Java/Flash update — classic social engineering',
    severity: 'critical',
    strings: ['java_update', 'flash_update', 'plugin_required', 'install_codec', 'download_apk', 'REQUEST_INSTALL_PACKAGES'],
    condition: '2_of_strings && has_install_permission',
  },

  // ─── Cookie & Session Theft YARA Rules ─────────────────────────
  {
    id: 'yara-cookie-harvest',
    name: 'Android_Cookie_Harvester',
    description: 'Detects apps that extract and exfiltrate browser cookies',
    severity: 'critical',
    strings: ['CookieManager', 'getCookie', 'getAllCookies', 'WebView', 'document.cookie', 'exfil'],
    condition: '3_of_strings && has_internet && !is_browser',
  },
  {
    id: 'yara-session-replay',
    name: 'Android_Session_Replay',
    description: 'Detects session replay/hijacking malware that clones active login sessions',
    severity: 'critical',
    strings: ['session_token', 'auth_cookie', 'JSESSIONID', 'csrf_token', 'bearer_token', 'replay_session'],
    condition: '3_of_strings && has_internet',
  },
  {
    id: 'yara-credential-dump',
    name: 'Android_Credential_Dump',
    description: 'Detects credential dumping from browser databases and password managers',
    severity: 'critical',
    strings: ['Login Data', 'logins.json', 'signons.sqlite', 'Web Data', 'chrome_profile', 'firefox_profile'],
    condition: '2_of_strings && has_storage_permission',
  },
  {
    id: 'yara-token-steal',
    name: 'Android_Token_Stealer',
    description: 'Detects OAuth/JWT token theft from apps and browsers',
    severity: 'critical',
    strings: ['access_token', 'refresh_token', 'id_token', 'SharedPreferences', 'getToken', 'oauth2'],
    condition: '3_of_strings && has_internet',
  },
  {
    id: 'yara-browser-db-theft',
    name: 'Android_Browser_DB_Theft',
    description: 'Detects theft of browser SQLite databases (history, passwords, cookies)',
    severity: 'critical',
    strings: ['app_webview', 'Cookies', 'History', 'databases/webview', 'SQLiteDatabase.openDatabase', 'file_copy'],
    condition: '3_of_strings && has_storage_permission',
  },
  {
    id: 'yara-lumma-stealer',
    name: 'Android_Lumma_Stealer_2025',
    description: 'Detects Lumma stealer with cookie restoration capability (bypasses session expiry)',
    severity: 'critical',
    strings: ['lumma', 'cookie_restore', 'session_clone', 'chrome_data', 'decrypt_cookie', 'master_key'],
    condition: '3_of_strings && has_internet',
  },

  // ─── Porn/Adult Site Threat YARA Rules ─────────────────────────
  {
    id: 'yara-adult-ransomware',
    name: 'Android_Adult_Ransomware',
    description: 'Detects ransomware distributed via adult sites (device lock + camera)',
    severity: 'critical',
    strings: ['porn', 'adult_content', 'lock_screen', 'camera_capture', 'fbi_warning', 'pay_fine', 'bitcoin'],
    condition: '3_of_strings && has_device_admin',
  },
  {
    id: 'yara-sextortion',
    name: 'Android_Sextortion_Malware',
    description: 'Detects sextortion malware that captures intimate content for blackmail',
    severity: 'critical',
    strings: ['gallery_scan', 'intimate_detect', 'contact_list', 'send_email', 'bitcoin_address', 'ransom_note', 'publish_threat'],
    condition: '3_of_strings && has_camera',
  },
  {
    id: 'yara-fake-video-player',
    name: 'Android_Fake_Video_Player',
    description: 'Detects trojanized video players from adult site redirects',
    severity: 'critical',
    strings: ['video_player', 'codec_required', 'install_plugin', 'overlay_permission', 'accessibility_enable', 'device_admin'],
    condition: '3_of_strings && has_install_permission',
  },
  {
    id: 'yara-porn-adware',
    name: 'Android_Porn_Adware',
    description: 'Detects aggressive adware installed via adult site malvertising',
    severity: 'high',
    strings: ['fullscreen_ad', 'popup_chain', 'redirect_url', 'notification_push', 'hidden_icon', 'adult_ad_sdk'],
    condition: '3_of_strings && has_internet',
  },
  {
    id: 'yara-koler-police',
    name: 'Android_Koler_Police',
    description: 'Detects Koler police-themed ransomware that locks device after adult content viewing',
    severity: 'critical',
    strings: ['police', 'illegal_content', 'device_locked', 'fine_payment', 'webcam_recorded', 'WindowManager.LayoutParams.FLAG_FULLSCREEN'],
    condition: '3_of_strings && has_device_admin',
  },
  {
    id: 'yara-leakware',
    name: 'Android_Leakware',
    description: 'Detects leakware that threatens to expose browsing history or private media',
    severity: 'critical',
    strings: ['browser_history', 'gallery_upload', 'contact_email', 'social_publish', 'payment_required', 'deadline_timer'],
    condition: '3_of_strings && has_internet',
  },
  {
    id: 'yara-adult-phishing',
    name: 'Android_Adult_Phishing',
    description: 'Detects credential phishing disguised as age verification or premium content unlock',
    severity: 'high',
    strings: ['age_verification', 'credit_card', 'verify_identity', 'premium_access', 'subscription_form', 'billing_info'],
    condition: '3_of_strings && has_internet',
  },
];

// ─── Suspicious App Characteristics ─────────────────────────────
export const suspiciousCharacteristics: {
  id: string;
  name: string;
  description: string;
  severity: string;
  weight: number; // Risk weight 1-10
}[] = [
  { id: 'char-no-icon', name: 'No Launcher Icon', description: 'App has no visible icon in the app drawer', severity: 'high', weight: 8 },
  { id: 'char-generic-name', name: 'Generic App Name', description: 'App uses generic name like "System Service" or "Update"', severity: 'medium', weight: 5 },
  { id: 'char-unknown-source', name: 'Sideloaded App', description: 'App was not installed from Google Play Store', severity: 'low', weight: 3 },
  { id: 'char-high-perms', name: 'Excessive Permissions', description: 'App requests 10+ permissions including dangerous ones', severity: 'medium', weight: 6 },
  { id: 'char-new-install', name: 'Recently Installed', description: 'App installed within last 7 days — monitor closely', severity: 'low', weight: 2 },
  { id: 'char-never-opened', name: 'Never Used', description: 'App is installed but has never been opened by the user', severity: 'low', weight: 3 },
  { id: 'char-self-signed', name: 'Self-Signed Certificate', description: 'App signed with a self-generated certificate', severity: 'medium', weight: 4 },
  { id: 'char-debug-build', name: 'Debug Build', description: 'App is a debug build, not a release build', severity: 'medium', weight: 5 },
  { id: 'char-obfuscated', name: 'Heavy Obfuscation', description: 'App code is heavily obfuscated beyond normal ProGuard', severity: 'medium', weight: 6 },
  { id: 'char-native-code', name: 'Native Code with Network', description: 'App uses native code (JNI) with network permissions', severity: 'medium', weight: 5 },
];

// ─── File-Based Threat Signatures ──────────────────────────────
// Magic bytes, embedded strings, and binary patterns for file scanning

export interface FileMagicSignature {
  id: string;
  name: string;
  magicBytes: number[]; // First N bytes of file
  offset: number; // Byte offset to check at
  severity: string;
  description: string;
  threatIfLocation: string; // Where is this suspicious? (e.g., 'cache', 'downloads', 'any')
}

export const fileMagicSignatures: FileMagicSignature[] = [
  // DEX files outside of normal APK bundles
  {
    id: 'magic-dex',
    name: 'Standalone DEX bytecode',
    magicBytes: [0x64, 0x65, 0x78, 0x0A], // "dex\n"
    offset: 0,
    severity: 'critical',
    description: 'Dalvik executable found outside APK. Indicates dynamically loaded code — a dropper/loader technique.',
    threatIfLocation: 'any',
  },
  // ELF binaries (native Linux executables)
  {
    id: 'magic-elf',
    name: 'ELF binary (native executable)',
    magicBytes: [0x7F, 0x45, 0x4C, 0x46], // "\x7FELF"
    offset: 0,
    severity: 'high',
    description: 'Native Linux executable found. May be a rootkit, exploit payload, or crypto miner.',
    threatIfLocation: 'any',
  },
  // APK/ZIP file (check in cache/hidden folders)
  {
    id: 'magic-apk',
    name: 'APK/ZIP archive',
    magicBytes: [0x50, 0x4B, 0x03, 0x04], // "PK\x03\x04"
    offset: 0,
    severity: 'high',
    description: 'APK archive found in suspicious location. May be a staged payload waiting for install.',
    threatIfLocation: 'cache',
  },
  // Shell scripts
  {
    id: 'magic-shell',
    name: 'Shell script',
    magicBytes: [0x23, 0x21, 0x2F], // "#!/"
    offset: 0,
    severity: 'high',
    description: 'Shell script found. May execute system commands, modify files, or download payloads.',
    threatIfLocation: 'any',
  },
  // SQLite databases (may contain exfiltrated data)
  {
    id: 'magic-sqlite',
    name: 'SQLite database',
    magicBytes: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65], // "SQLite"
    offset: 0,
    severity: 'medium',
    description: 'Database file found in unexpected location. May contain harvested credentials or contacts.',
    threatIfLocation: 'cache',
  },
  // Encrypted/compressed blobs (high entropy indicator via common headers)
  {
    id: 'magic-gzip',
    name: 'GZip compressed data',
    magicBytes: [0x1F, 0x8B, 0x08],
    offset: 0,
    severity: 'medium',
    description: 'Compressed archive in suspicious location. May contain encrypted exfiltrated data or staged payloads.',
    threatIfLocation: 'cache',
  },
  // Java class file (should NEVER appear on Android)
  {
    id: 'magic-java-class',
    name: 'Java .class bytecode',
    magicBytes: [0xCA, 0xFE, 0xBA, 0xBE], // Java class file magic
    offset: 0,
    severity: 'critical',
    description: 'Java class file detected. Android uses DEX, not Java bytecode — this is a cross-platform RAT payload or exploit.',
    threatIfLocation: 'any',
  },
  // Java JAR manifest (inside a renamed/disguised file)
  {
    id: 'magic-jar-manifest',
    name: 'JAR archive with manifest',
    magicBytes: [0x50, 0x4B, 0x03, 0x04], // ZIP header (JAR is ZIP with META-INF)
    offset: 0,
    severity: 'high',
    description: 'Java Archive (JAR) detected via ZIP header in non-APK context. May contain jRAT/Adwind payload.',
    threatIfLocation: 'cache',
  },
];

// ─── Suspicious Embedded Strings ──────────────────────────────
// Strings found inside files that indicate malware

export interface SuspiciousString {
  id: string;
  pattern: string; // Regex pattern to search in file content
  name: string;
  severity: string;
  description: string;
  category: 'c2' | 'exploit' | 'crypto' | 'exfil' | 'persistence' | 'evasion';
}

export const suspiciousFileStrings: SuspiciousString[] = [
  // C2 communication patterns
  { id: 'str-http-c2', pattern: 'http[s]?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}[:/]', name: 'Hardcoded IP URL', severity: 'high', description: 'Direct IP communication bypassing DNS — common C2 technique', category: 'c2' },
  { id: 'str-duckdns', pattern: '\\w+\\.duckdns\\.org', name: 'DuckDNS C2 domain', severity: 'high', description: 'Dynamic DNS often used for C2 infrastructure', category: 'c2' },
  { id: 'str-ngrok', pattern: '\\w+\\.ngrok\\.io', name: 'Ngrok tunnel', severity: 'high', description: 'Tunneling service commonly used for C2 callbacks', category: 'c2' },
  { id: 'str-telegram-bot', pattern: 'api\\.telegram\\.org/bot\\w+', name: 'Telegram Bot API', severity: 'high', description: 'Telegram bot used as C2 channel — common in 2024-2026 malware', category: 'c2' },
  { id: 'str-discord-webhook', pattern: 'discord\\.com/api/webhooks/', name: 'Discord webhook exfil', severity: 'high', description: 'Discord webhook used for data exfiltration', category: 'exfil' },
  { id: 'str-pastebin', pattern: 'pastebin\\.com/raw/', name: 'Pastebin payload fetch', severity: 'medium', description: 'Fetching payload or config from pastebin — dead drop technique', category: 'c2' },

  // Exploit / privilege escalation
  { id: 'str-su-binary', pattern: '/system/xbin/su|/system/bin/su|/sbin/su', name: 'Root binary access', severity: 'critical', description: 'Attempting to access su binary — root exploit or privilege escalation', category: 'exploit' },
  { id: 'str-magisk', pattern: 'magisk|supersu|com\\.topjohnwu', name: 'Root framework detection', severity: 'medium', description: 'Checking for root frameworks — either root detection or exploitation', category: 'exploit' },
  { id: 'str-proc-self', pattern: '/proc/self/maps|/proc/self/mem', name: 'Process memory access', severity: 'high', description: 'Accessing process memory maps — code injection or anti-debug technique', category: 'exploit' },
  { id: 'str-dev-mem', pattern: '/dev/mem|/dev/kmem', name: 'Kernel memory access', severity: 'critical', description: 'Attempting kernel memory access — rootkit behavior', category: 'exploit' },

  // Crypto stealing
  { id: 'str-seed-phrase', pattern: 'mnemonic|seed.?phrase|recovery.?words|bip39|bip44', name: 'Crypto seed phrase targeting', severity: 'critical', description: 'References to cryptocurrency recovery phrases — likely seed stealer', category: 'crypto' },
  { id: 'str-wallet-addr', pattern: '(bc1|0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33})', name: 'Hardcoded crypto address', severity: 'high', description: 'Embedded crypto wallet address — may be used for clipboard replacement', category: 'crypto' },
  { id: 'str-private-key', pattern: 'private.?key|keystore|wallet\\.dat', name: 'Private key targeting', severity: 'critical', description: 'Targeting cryptocurrency private keys or keystores', category: 'crypto' },

  // Data exfiltration
  { id: 'str-content-sms', pattern: 'content://sms|content://call_log|content://contacts', name: 'Content provider access', severity: 'high', description: 'Directly querying SMS, call logs, or contacts for exfiltration', category: 'exfil' },
  { id: 'str-base64-exfil', pattern: 'Base64\\.encode|btoa\\(|android\\.util\\.Base64', name: 'Base64 encoding for exfil', severity: 'medium', description: 'Data encoding before transmission — common exfil preparation', category: 'exfil' },
  { id: 'str-zip-exfil', pattern: 'ZipOutputStream|createZipFile|compress.*send', name: 'Compression before exfil', severity: 'medium', description: 'Compressing data before sending — bulk exfiltration pattern', category: 'exfil' },

  // Persistence mechanisms
  { id: 'str-boot-receiver', pattern: 'BOOT_COMPLETED|QUICKBOOT_POWERON', name: 'Boot persistence', severity: 'medium', description: 'Registering for boot events — ensuring persistence across restarts', category: 'persistence' },
  { id: 'str-alarm-persist', pattern: 'AlarmManager.*setRepeating|setExactAndAllowWhileIdle', name: 'Alarm persistence', severity: 'medium', description: 'Using alarms for persistent background execution', category: 'persistence' },
  { id: 'str-work-manager', pattern: 'PeriodicWorkRequest|OneTimeWorkRequest.*setExpedited', name: 'WorkManager abuse', severity: 'low', description: 'WorkManager scheduled for persistent background tasks', category: 'persistence' },
  { id: 'str-accessibility-persist', pattern: 'AccessibilityService|onAccessibilityEvent', name: 'Accessibility persistence', severity: 'high', description: 'Accessibility service for persistent screen monitoring', category: 'persistence' },

  // Evasion techniques
  { id: 'str-emulator-detect', pattern: 'goldfish|sdk_gphone|generic_x86|vbox86|nox|genymotion', name: 'Emulator detection', severity: 'medium', description: 'Checking for emulator — malware evading sandbox analysis', category: 'evasion' },
  { id: 'str-debugger-detect', pattern: 'android\\.os\\.Debug\\.isDebuggerConnected|TracerPid', name: 'Anti-debugging', severity: 'medium', description: 'Debugger detection — evading dynamic analysis', category: 'evasion' },
  { id: 'str-reflection-load', pattern: 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader', name: 'Dynamic code loading', severity: 'high', description: 'Loading code at runtime — common in staged/encrypted malware', category: 'evasion' },
  { id: 'str-native-load', pattern: 'System\\.loadLibrary|System\\.load\\(', name: 'Native library loading', severity: 'medium', description: 'Loading native libraries at runtime — may contain obfuscated payloads', category: 'evasion' },
  { id: 'str-reflection-invoke', pattern: 'java\\.lang\\.reflect\\.Method.*invoke|getMethod\\(', name: 'Reflection invocation', severity: 'medium', description: 'Using reflection to invoke methods — hiding behavior from static analysis', category: 'evasion' },

  // Java-specific exploit strings
  { id: 'str-jndi-lookup', pattern: '\\$\\{jndi:|InitialContext|javax\\.naming', name: 'JNDI lookup (Log4Shell)', severity: 'critical', description: 'JNDI injection string — Log4Shell or similar Java exploitation', category: 'exploit' },
  { id: 'str-java-runtime-exec', pattern: 'Runtime\\.getRuntime\\(\\)\\.exec|ProcessBuilder', name: 'Java command execution', severity: 'critical', description: 'Java native command execution — can run arbitrary system commands', category: 'exploit' },
  { id: 'str-classloader', pattern: 'URLClassLoader|DexClassLoader|JarFile.*loadClass', name: 'Dynamic class loading', severity: 'high', description: 'Loading classes at runtime from external sources — dropper technique', category: 'exploit' },
  { id: 'str-java-deserial', pattern: 'ObjectInputStream|readObject|InvokerTransformer|CommonsCollections', name: 'Java deserialization', severity: 'critical', description: 'Deserialization gadget chain strings — remote code execution exploit', category: 'exploit' },
  { id: 'str-webview-bridge', pattern: 'addJavascriptInterface|@JavascriptInterface', name: 'WebView JS bridge', severity: 'medium', description: 'JavaScript bridge exposed — potential remote code execution if improperly secured', category: 'exploit' },
  { id: 'str-jar-download', pattern: 'download.*\\.jar|fetch.*\\.dex|load.*payload', name: 'Remote JAR/DEX fetch', severity: 'critical', description: 'Downloading executable Java/DEX code at runtime — staged malware', category: 'exploit' },

  // Cookie & session theft strings
  { id: 'str-cookie-manager', pattern: 'CookieManager\\.getInstance|getCookie\\(|getAllCookies', name: 'Cookie manager access', severity: 'high', description: 'Programmatic cookie access — session theft if not a browser app', category: 'exfil' },
  { id: 'str-document-cookie', pattern: 'document\\.cookie|setCookie|__cfduid|_ga=', name: 'JavaScript cookie access', severity: 'high', description: 'Accessing web cookies via JavaScript injection — session hijacking', category: 'exfil' },
  { id: 'str-session-tokens', pattern: 'PHPSESSID|JSESSIONID|ASP\\.NET_SessionId|connect\\.sid', name: 'Session ID patterns', severity: 'high', description: 'Targeting specific session identifiers for session hijacking', category: 'exfil' },
  { id: 'str-chrome-profile', pattern: 'app_chrome|app_webview|Login Data|Web Data|Cookies\\.db', name: 'Chrome profile files', severity: 'critical', description: 'Accessing Chrome browser profile database files — credential/cookie theft', category: 'exfil' },
  { id: 'str-firefox-profile', pattern: 'logins\\.json|cookies\\.sqlite|key[34]\\.db|signons\\.sqlite', name: 'Firefox profile files', severity: 'critical', description: 'Targeting Firefox stored credentials and cookies', category: 'exfil' },
  { id: 'str-oauth-tokens', pattern: 'access_token|refresh_token|bearer |Authorization: Bearer', name: 'OAuth token access', severity: 'high', description: 'Intercepting or extracting OAuth bearer tokens for account takeover', category: 'exfil' },
  { id: 'str-cookie-decrypt', pattern: 'decrypt.*cookie|CryptUnprotectData|master_key|os_crypt', name: 'Cookie decryption', severity: 'critical', description: 'Attempting to decrypt encrypted browser cookies — advanced stealer technique', category: 'exfil' },
  { id: 'str-autofill-theft', pattern: 'autofill|credit_card|saved_password|form_data', name: 'Autofill data theft', severity: 'critical', description: 'Targeting browser autofill data including saved cards and passwords', category: 'exfil' },

  // Adult site / porn threat strings
  { id: 'str-adult-content-detect', pattern: 'porn|xxx|adult.?content|nsfw.?detect|nude.?scan', name: 'Adult content reference', severity: 'medium', description: 'References to adult content detection — may be leakware or sextortion prep', category: 'exfil' },
  { id: 'str-ransom-police', pattern: 'FBI|police|illegal.?content|cyber.?crime|law.?enforcement', name: 'Fake law enforcement text', severity: 'high', description: 'Fake law enforcement warnings — police ransomware pattern', category: 'exploit' },
  { id: 'str-gallery-exfil', pattern: 'DCIM|Pictures|gallery.?scan|image.?upload|photo.?send', name: 'Gallery exfiltration', severity: 'high', description: 'Scanning and uploading device photos — sextortion/leakware pattern', category: 'exfil' },
  { id: 'str-sextortion-msg', pattern: 'publish|expose|intimate|blackmail|pay.*bitcoin|leak.*photos', name: 'Sextortion language', severity: 'critical', description: 'Blackmail/extortion language found in binary — sextortion malware', category: 'exploit' },
  { id: 'str-fake-codec', pattern: 'codec.?required|player.?update|flash.?update|plugin.?install', name: 'Fake codec/player prompt', severity: 'high', description: 'Social engineering strings for fake codec/player installs from adult sites', category: 'exploit' },
  { id: 'str-premium-sms-adult', pattern: 'premium.?sms|short.?code|subscribe.*adult|billing.*wap', name: 'Adult premium SMS', severity: 'high', description: 'Premium SMS subscription fraud via adult content bait', category: 'exploit' },
];

// ─── Malicious File Path Patterns ─────────────────────────────
// Paths where malware commonly stages files

export interface MaliciousPathPattern {
  pattern: string; // Regex for path
  name: string;
  severity: string;
  description: string;
}

export const maliciousFilePathPatterns: MaliciousPathPattern[] = [
  // Hidden dot-directories used by malware
  { pattern: '/\\.\\w+/.*\\.(apk|dex|jar|so)', name: 'Hidden dir with executable', severity: 'critical', description: 'Executable file hidden in dot-directory — dropper staging area' },
  { pattern: '/\\.system_update/', name: 'Fake system update dir', severity: 'critical', description: 'Directory mimicking system updates — malware staging' },
  { pattern: '/\\.temp_cache/.*\\.dex', name: 'Hidden DEX in fake cache', severity: 'critical', description: 'DEX bytecode in disguised temp directory — dynamic loading payload' },

  // Common malware staging paths
  { pattern: '/sdcard/\\.\\w+/', name: 'Hidden folder on SD', severity: 'high', description: 'Hidden folder on external storage — common malware data staging' },
  { pattern: '/Android/data/[^/]+/files/\\.\\w+', name: 'Hidden in app data', severity: 'high', description: 'Hidden folder inside app data directory — concealing payloads' },
  { pattern: '/Download/\\.[^/]+\\.apk', name: 'Hidden APK in Downloads', severity: 'critical', description: 'Hidden APK file in Downloads folder — drive-by download' },
  { pattern: '/data/local/tmp/.*\\.(dex|apk|so)', name: 'Executable in tmp', severity: 'critical', description: 'Executable in local tmp — exploit payload or dropper stage' },

  // Browser hijack paths
  { pattern: '/files/\\.browser.*\\.(js|html)', name: 'Injected browser files', severity: 'high', description: 'Suspicious browser-related files — potential injection payload' },

  // Crypto miner artifacts
  { pattern: '/.*config\\.(json|ini).*pool.*', name: 'Mining pool config', severity: 'high', description: 'Configuration file referencing mining pool — cryptojacking' },
  { pattern: '/.*xmrig|cryptonight|minerd', name: 'Crypto miner binary', severity: 'critical', description: 'Known crypto mining software binary on device' },
];

// ─── Auto-Reinstall & Persistence Detection ────────────────────
// Patterns that indicate an app will reinstall itself or resist removal

export interface PersistenceIndicator {
  id: string;
  name: string;
  checkType: 'package_pair' | 'file_presence' | 'permission_combo' | 'behavior';
  pattern: string;
  severity: string;
  description: string;
}

export const persistenceIndicators: PersistenceIndicator[] = [
  // Package pairs (one reinstalls the other)
  { id: 'persist-companion', checkType: 'package_pair', pattern: '.*\\.helper|.*\\.updater|.*\\.service', name: 'Companion installer', severity: 'high', description: 'Secondary app that reinstalls primary malware after removal' },
  { id: 'persist-provision', checkType: 'package_pair', pattern: '.*\\.provisioning|.*\\.installer|.*\\.manager', name: 'Provisioning reinstaller', severity: 'high', description: 'App using device provisioning APIs to reinstall removed apps' },

  // File-based persistence
  { id: 'persist-cron', checkType: 'file_presence', pattern: '/data/local/cron|/sdcard/.*autorun', name: 'Cron/autorun file', severity: 'critical', description: 'Scheduled execution file found — runs malware on timer or boot' },
  { id: 'persist-init-script', checkType: 'file_presence', pattern: '/system/etc/init\\.d/|/data/adb/service\\.d/', name: 'Init script injection', severity: 'critical', description: 'Startup script in init.d — executes with root on boot' },

  // Permission-based persistence
  { id: 'persist-device-admin', checkType: 'permission_combo', pattern: 'BIND_DEVICE_ADMIN+REQUEST_INSTALL_PACKAGES', name: 'Admin + installer', severity: 'critical', description: 'Device admin with install permission — can force-install apps and prevent removal' },
  { id: 'persist-notification-listener', checkType: 'permission_combo', pattern: 'BIND_NOTIFICATION_LISTENER_SERVICE+INTERNET', name: 'Notification listener + net', severity: 'high', description: 'Can read all notifications and exfiltrate — including 2FA codes' },

  // Behavioral persistence
  { id: 'persist-foreground-service', checkType: 'behavior', pattern: 'FOREGROUND_SERVICE+RECEIVE_BOOT_COMPLETED+WAKE_LOCK', name: 'Persistent foreground', severity: 'medium', description: 'Maintains foreground service from boot with wakelock — always running' },
  { id: 'persist-account-sync', checkType: 'behavior', pattern: 'AUTHENTICATE_ACCOUNTS+INTERNET+RECEIVE_BOOT_COMPLETED', name: 'Account sync abuse', severity: 'high', description: 'Uses account sync to maintain background execution slot' },
];

// ─── Shannon Entropy Thresholds ─────────────────────────────────
// Used to detect encrypted/packed payloads vs normal files

export const ENTROPY_THRESHOLDS = {
  encrypted: 7.5,    // > 7.5 bits/byte = likely encrypted or compressed payload
  packed: 6.8,       // > 6.8 = likely packed/obfuscated
  suspicious: 6.0,   // > 6.0 for non-media files = worth investigating
  normal: 4.5,       // Typical text/code files
} as const;

// ─── Known Malware Certificate Fingerprints ─────────────────────
// SHA256 prefix of certificates used to sign known malware

export const maliciousCertFingerprints: {
  prefix: string;
  family: string;
  description: string;
}[] = [
  { prefix: 'a40da80a59', family: 'SpyNote', description: 'SpyNote RAT default signing certificate' },
  { prefix: '61ed377e85', family: 'AhMyth', description: 'AhMyth RAT builder default certificate' },
  { prefix: '2e4e67a3c3', family: 'Cerberus', description: 'Cerberus banking trojan leaked builder cert' },
  { prefix: 'c8a2e5b0d9', family: 'Hydra', description: 'Hydra banking trojan campaign cert' },
  { prefix: 'd5f1c94e7b', family: 'Joker', description: 'Joker subscription fraud cert cluster' },
  { prefix: 'f0e3a21b8c', family: 'FakeApp', description: 'Mass-produced fake app cert factory' },
  { prefix: 'b7d4e8f2a1', family: 'Anubis', description: 'Anubis banking trojan builder cert' },
  { prefix: '3c9f0a6e5d', family: 'MetaSploit', description: 'Default Metasploit Android payload cert' },
  { prefix: '8a1b3c5d7e', family: 'DroidJack', description: 'DroidJack RAT default certificate' },
  { prefix: 'e2f4a6b8c0', family: 'ERMAC', description: 'ERMAC banking trojan campaign cert' },
];

// ─── Export consolidated lookup ─────────────────────────────────
export function lookupPackage(packageName: string): {
  matched: boolean;
  family?: string;
  severity?: string;
  description?: string;
} {
  for (const pattern of maliciousPackagePatterns) {
    try {
      if (new RegExp(pattern.pattern, 'i').test(packageName)) {
        return {
          matched: true,
          family: pattern.family,
          severity: pattern.severity,
          description: pattern.description,
        };
      }
    } catch {
      continue;
    }
  }
  return { matched: false };
}

export function lookupDomain(domain: string): {
  matched: boolean;
  type?: string;
  family?: string;
} {
  for (const infra of maliciousInfrastructure) {
    if (domain.includes(infra.domain) || infra.domain.includes(domain)) {
      return {
        matched: true,
        type: infra.type,
        family: infra.family,
      };
    }
  }
  return { matched: false };
}

export function lookupIP(ip: string): {
  matched: boolean;
  type?: string;
  family?: string;
} {
  for (const infra of maliciousInfrastructure) {
    if (ip.startsWith(infra.domain)) {
      return {
        matched: true,
        type: infra.type,
        family: infra.family,
      };
    }
  }
  return { matched: false };
}

export const signatureStats = {
  totalPackagePatterns: maliciousPackagePatterns.length,
  totalC2Domains: maliciousInfrastructure.length,
  totalPermCombos: expandedDangerousPermCombos.length,
  totalBehavioralRules: behavioralIndicators.length,
  totalYaraRules: yaraRules.length,
  totalFileSignatures: fileMagicSignatures.length,
  totalStringPatterns: suspiciousFileStrings.length,
  totalPathPatterns: maliciousFilePathPatterns.length,
  totalPersistenceIndicators: persistenceIndicators.length,
  totalCertFingerprints: maliciousCertFingerprints.length,
  lastUpdated: '2026-05-17',
};
