import React, { useState, useEffect, useCallback } from 'react';
import {
  View, Text, ScrollView, StyleSheet, TouchableOpacity, Switch, Alert,
  TextInput, Linking, ActivityIndicator,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../types/navigation';
import { colors, spacing, borderRadius, layout } from '../theme';
import GlassCard from '../components/common/GlassCard';
import {
  getSchedule, enableSchedule, disableSchedule, toggleDailyDigest,
  getNextScanLabel, getHistoryStats, clearScanHistory,
  type ScheduleFrequency, type ScanSchedule,
} from '../utils/scheduler';
import { requestNotificationPermissions } from '../utils/notifications';
import { signatureStats } from '../data/signatures';
import {
  getLanguage, setLanguage, AVAILABLE_LANGUAGES,
  type SupportedLanguage,
} from '../i18n';
import {
  getAIConfig, setAIConsent, setAIKey, AI_PROVIDERS,
  type AIProvider, type AIConfig,
} from '../utils/aiConfig';
import { testProvider } from '../utils/aiAnalysis';
import {
  getOfflineAIConfig, setOfflineAIEnabled, isModelDownloaded,
  downloadModel, deleteModel, getModelStorageUsage,
  RESOURCE_REQUIREMENTS, OFFLINE_MODEL_INFO,
  type OfflineAIConfig,
} from '../utils/aiOffline';

type FreqOption = { id: ScheduleFrequency; label: string; desc: string };

const FREQ_OPTIONS: FreqOption[] = [
  { id: 'manual', label: 'Manual', desc: 'Scan only when you tap the button' },
  { id: 'daily', label: 'Daily', desc: 'Scan once every 24 hours' },
  { id: 'weekly', label: 'Weekly', desc: 'Scan once every 7 days' },
  { id: 'biweekly', label: 'Bi-weekly', desc: 'Scan once every 14 days' },
  { id: 'monthly', label: 'Monthly', desc: 'Scan once every 30 days' },
];

// ─── Settings Row ───────────────────────────────────────────────
function SettingsRow({
  icon, iconColor, title, subtitle, right,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  iconColor?: string;
  title: string;
  subtitle?: string;
  right?: React.ReactNode;
}) {
  return (
    <View style={styles.settingsRow}>
      <View style={[styles.settingsIcon, { backgroundColor: (iconColor || colors.accentMint) + '18' }]}>
        <Ionicons name={icon} size={18} color={iconColor || colors.accentMint} />
      </View>
      <View style={styles.settingsText}>
        <Text style={styles.settingsTitle}>{title}</Text>
        {subtitle && <Text style={styles.settingsSubtitle}>{subtitle}</Text>}
      </View>
      {right && <View style={styles.settingsRight}>{right}</View>}
    </View>
  );
}

// ─── Touchable Settings Row ───────────────────────────────────────
function TouchableSettingsRow({
  icon, iconColor, title, subtitle, onPress,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  iconColor?: string;
  title: string;
  subtitle?: string;
  onPress: () => void;
}) {
  return (
    <TouchableOpacity style={styles.settingsRow} onPress={onPress}>
      <View style={[styles.settingsIcon, { backgroundColor: (iconColor || colors.accentMint) + '18' }]}>
        <Ionicons name={icon} size={18} color={iconColor || colors.accentMint} />
      </View>
      <View style={styles.settingsText}>
        <Text style={styles.settingsTitle}>{title}</Text>
        {subtitle && <Text style={styles.settingsSubtitle}>{subtitle}</Text>}
      </View>
      <View style={styles.settingsRight}>
        <Ionicons name="chevron-forward" size={16} color={colors.textMuted} />
      </View>
    </TouchableOpacity>
  );
}

// ─── Stat Box ───────────────────────────────────────────────────
function StatBox({ value, label, color }: { value: string | number; label: string; color?: string }) {
  return (
    <View style={styles.statBox}>
      <Text style={[styles.statValue, color ? { color } : undefined]}>{value}</Text>
      <Text style={styles.statLabel}>{label}</Text>
    </View>
  );
}

// ─── Main Screen ────────────────────────────────────────────────
export default function SettingsScreen() {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const [schedule, setSchedule] = useState<ScanSchedule | null>(null);
  const [notificationsEnabled, setNotificationsEnabled] = useState(false);
  const [historyStats, setHistoryStats] = useState<any>(null);
  const [currentLang, setCurrentLang] = useState<SupportedLanguage>(getLanguage());
  const [aiConfig, setAiConfig] = useState<AIConfig | null>(null);
  const [aiKeyInputs, setAiKeyInputs] = useState<Record<AIProvider, string>>({
    gemini: '', groq: '', glm: '', openrouter: '',
  });
  const [testingProvider, setTestingProvider] = useState<AIProvider | null>(null);
  const [offlineConfig, setOfflineConfig] = useState<OfflineAIConfig>({ enabled: false, modelDownloaded: false });
  const [offlineDownloading, setOfflineDownloading] = useState(false);
  const [offlineProgress, setOfflineProgress] = useState(0);
  const [offlineStorageUsed, setOfflineStorageUsed] = useState(0);

  const handleLanguageChange = useCallback(async (lang: SupportedLanguage) => {
    await setLanguage(lang);
    setCurrentLang(lang);
  }, []);

  useEffect(() => {
    loadSettings();
    loadAIConfig();
    loadOfflineConfig();
  }, []);

  const loadAIConfig = async () => {
    const config = await getAIConfig();
    setAiConfig(config);
    setAiKeyInputs({
      gemini: config.geminiKey,
      groq: config.groqKey,
      glm: config.glmKey,
      openrouter: config.openrouterKey,
    });
  };

  const handleAIConsent = useCallback(async (enabled: boolean) => {
    await setAIConsent(enabled);
    setAiConfig((prev) => prev ? { ...prev, consentGiven: enabled } : prev);
  }, []);

  const handleSaveKey = useCallback(async (provider: AIProvider) => {
    const key = aiKeyInputs[provider];
    await setAIKey(provider, key);
    await loadAIConfig();
    Alert.alert('Saved', `${provider.charAt(0).toUpperCase() + provider.slice(1)} API key saved.`);
  }, [aiKeyInputs]);

  const handleTestProvider = useCallback(async (provider: AIProvider) => {
    const key = aiKeyInputs[provider];
    if (!key) {
      Alert.alert('No Key', 'Enter an API key first.');
      return;
    }
    setTestingProvider(provider);
    const result = await testProvider(provider, key);
    setTestingProvider(null);
    Alert.alert(
      result.success ? 'Connected' : 'Failed',
      result.message,
    );
  }, [aiKeyInputs]);

  const loadOfflineConfig = async () => {
    const config = await getOfflineAIConfig();
    setOfflineConfig(config);
    const usage = await getModelStorageUsage();
    setOfflineStorageUsed(usage);
  };

  const handleOfflineToggle = useCallback(async (enabled: boolean) => {
    if (enabled) {
      // Show resource disclosure before enabling
      Alert.alert(
        'On-Device AI Model',
        `This will download a ${RESOURCE_REQUIREMENTS.downloadSize} AI model to your device.\n\n` +
        `Requirements:\n` +
        `• Storage: ${RESOURCE_REQUIREMENTS.storageRequired}\n` +
        `• RAM during analysis: ${RESOURCE_REQUIREMENTS.ramDuringInference}\n` +
        `• CPU: ${RESOURCE_REQUIREMENTS.cpuUsage}\n` +
        `• Battery: ${RESOURCE_REQUIREMENTS.batteryImpact}\n` +
        `• Recommended: ${RESOURCE_REQUIREMENTS.recommendedRAM}\n\n` +
        `Model: ${RESOURCE_REQUIREMENTS.modelName} (${RESOURCE_REQUIREMENTS.quantization})\n\n` +
        `${RESOURCE_REQUIREMENTS.note}`,
        [
          { text: 'Cancel', style: 'cancel' },
          {
            text: 'Enable & Download',
            onPress: async () => {
              await setOfflineAIEnabled(true);
              setOfflineConfig((prev) => ({ ...prev, enabled: true }));
              handleDownloadModel();
            },
          },
        ],
      );
    } else {
      await setOfflineAIEnabled(false);
      setOfflineConfig((prev) => ({ ...prev, enabled: false }));
    }
  }, []);

  const handleDownloadModel = useCallback(async () => {
    setOfflineDownloading(true);
    setOfflineProgress(0);
    const result = await downloadModel((progress) => {
      setOfflineProgress(progress);
    });
    setOfflineDownloading(false);
    if (result.success) {
      setOfflineConfig((prev) => ({ ...prev, modelDownloaded: true }));
      const usage = await getModelStorageUsage();
      setOfflineStorageUsed(usage);
      Alert.alert('Download Complete', 'On-device AI model is ready. Analyses will now work offline.');
    } else {
      Alert.alert('Download Failed', result.error || 'Could not download model. Check your connection and try again.');
    }
  }, []);

  const handleDeleteModel = useCallback(async () => {
    Alert.alert(
      'Delete Offline Model',
      `This will free ${RESOURCE_REQUIREMENTS.storageRequired} of storage. You can re-download later.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            await deleteModel();
            setOfflineConfig((prev) => ({ ...prev, modelDownloaded: false }));
            setOfflineStorageUsed(0);
            Alert.alert('Deleted', 'Offline model removed.');
          },
        },
      ],
    );
  }, []);

  const loadSettings = async () => {
    const sched = await getSchedule();
    setSchedule(sched);
    const stats = await getHistoryStats();
    setHistoryStats(stats);
  };

  const handleToggleSchedule = useCallback(async (enabled: boolean) => {
    if (enabled) {
      const granted = await requestNotificationPermissions();
      if (!granted) {
        Alert.alert('Permissions Required', 'Notification permission is needed for scan reminders.');
        return;
      }
      setNotificationsEnabled(true);
      const freq = schedule?.frequency || 'weekly';
      const newSchedule = await enableSchedule(freq);
      setSchedule(newSchedule);
    } else {
      const newSchedule = await disableSchedule();
      setSchedule(newSchedule);
    }
  }, [schedule]);

  const handleFrequencyChange = useCallback(async (freq: ScheduleFrequency) => {
    if (!schedule?.enabled && freq !== 'manual') {
      const granted = await requestNotificationPermissions();
      if (!granted) {
        Alert.alert('Permissions Required', 'Enable notifications for scheduled scans.');
        return;
      }
      setNotificationsEnabled(true);
    }

    if (freq === 'manual') {
      const newSchedule = await disableSchedule();
      setSchedule({ ...newSchedule, frequency: 'manual' });
    } else {
      const newSchedule = await enableSchedule(freq);
      setSchedule(newSchedule);
    }
  }, [schedule]);

  const handleToggleDigest = useCallback(async (enabled: boolean) => {
    await toggleDailyDigest(enabled);
    if (schedule) {
      setSchedule({ ...schedule, dailyDigestEnabled: enabled });
    }
  }, [schedule]);

  const handleClearHistory = useCallback(() => {
    Alert.alert(
      'Clear Scan History',
      'This will permanently delete all scan history. Continue?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Clear',
          style: 'destructive',
          onPress: async () => {
            await clearScanHistory();
            setHistoryStats(await getHistoryStats());
          },
        },
      ]
    );
  }, []);

  const handleEnableNotifications = useCallback(async () => {
    const granted = await requestNotificationPermissions();
    setNotificationsEnabled(granted);
    if (!granted) {
      Alert.alert('Permission Denied', 'You can enable notifications in your device settings.');
    }
  }, []);

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      {/* Header */}
      <Text style={styles.headerTitle}>Settings</Text>
      <Text style={styles.headerSub}>Configure scan schedule, notifications, threat database, and AI agents.</Text>

      {/* ── Scan Stats ────────────────────────────────────── */}
      <Text style={styles.sectionLabel}>PREMIUM FEATURES</Text>
      <GlassCard>
        <TouchableSettingsRow
          icon="eye-off"
          iconColor={colors.accentInfo}
          title="Ghost Mode (Camouflage)"
          subtitle="Hide the app icon and rename it"
          onPress={() => navigation.navigate('GhostModeSettings')}
        />
        <View style={styles.divider} />
        <TouchableSettingsRow
          icon="finger-print"
          iconColor={colors.accentWarning}
          title="App Locker & Intruder Trap"
          subtitle="Biometric lock and unauthorized access capture"
          onPress={() => navigation.navigate('LockerScreen')}
        />
      </GlassCard>

      <Text style={styles.sectionLabel}>SCAN STATISTICS</Text>
      <GlassCard>
        <View style={styles.statsGrid}>
          <StatBox value={historyStats?.totalScans ?? 0} label="Total Scans" color={colors.accentMint} />
          <StatBox value={historyStats?.avgRiskScore ?? 0} label="Avg Risk" color={colors.accentWarning} />
          <StatBox value={historyStats?.criticalThreatCount ?? 0} label="Critical" color={colors.accentDanger} />
          <StatBox value={historyStats?.lastScanDate ?? '—'} label="Last Scan" />
        </View>
      </GlassCard>

      {/* ── Scan Schedule ─────────────────────────────────── */}
      <Text style={styles.sectionLabel}>SCAN SCHEDULE</Text>
      <GlassCard>
        <SettingsRow
          icon="timer"
          title="Auto Scan"
          subtitle={schedule?.enabled ? `Next: ${getNextScanLabel(schedule)}` : 'Disabled'}
          right={
            <Switch
              value={schedule?.enabled || false}
              onValueChange={handleToggleSchedule}
              trackColor={{ false: colors.bgSurface, true: colors.accentMint + '60' }}
              thumbColor={schedule?.enabled ? colors.accentMint : colors.textMuted}
            />
          }
        />

        <View style={styles.divider} />

        <Text style={styles.freqLabel}>Scan Frequency</Text>
        <View style={styles.freqGrid}>
          {FREQ_OPTIONS.map((opt) => (
            <TouchableOpacity
              key={opt.id}
              onPress={() => handleFrequencyChange(opt.id)}
              style={[
                styles.freqPill,
                schedule?.frequency === opt.id && styles.freqPillActive,
              ]}
            >
              <Text style={[
                styles.freqPillText,
                schedule?.frequency === opt.id && styles.freqPillTextActive,
              ]}>
                {opt.label}
              </Text>
            </TouchableOpacity>
          ))}
        </View>

        {schedule?.frequency && schedule.frequency !== 'manual' && (
          <Text style={styles.freqDesc}>
            {FREQ_OPTIONS.find((o) => o.id === schedule.frequency)?.desc}
          </Text>
        )}
      </GlassCard>

      {/* ── Notifications ─────────────────────────────────── */}
      <Text style={styles.sectionLabel}>NOTIFICATIONS</Text>
      <GlassCard>
        <SettingsRow
          icon="notifications"
          iconColor={colors.accentWarning}
          title="Push Notifications"
          subtitle="Get alerts for scan results and threats"
          right={
            <Switch
              value={notificationsEnabled}
              onValueChange={handleEnableNotifications}
              trackColor={{ false: colors.bgSurface, true: colors.accentWarning + '60' }}
              thumbColor={notificationsEnabled ? colors.accentWarning : colors.textMuted}
            />
          }
        />

        <View style={styles.divider} />

        <SettingsRow
          icon="newspaper"
          iconColor={colors.accentInfo}
          title="Daily Security Digest"
          subtitle="Morning summary of device security status"
          right={
            <Switch
              value={schedule?.dailyDigestEnabled || false}
              onValueChange={handleToggleDigest}
              trackColor={{ false: colors.bgSurface, true: colors.accentInfo + '60' }}
              thumbColor={schedule?.dailyDigestEnabled ? colors.accentInfo : colors.textMuted}
            />
          }
        />

        <View style={styles.divider} />

        <SettingsRow
          icon="alert-circle"
          iconColor={colors.accentDanger}
          title="Critical Threat Alerts"
          subtitle="Immediate alerts for critical findings"
          right={
            <Switch
              value={true}
              disabled={true}
              trackColor={{ false: colors.bgSurface, true: colors.accentDanger + '60' }}
              thumbColor={colors.accentDanger}
            />
          }
        />
      </GlassCard>

      {/* ── Threat Database ───────────────────────────────── */}
      <Text style={styles.sectionLabel}>THREAT DATABASE</Text>
      <GlassCard>
        <SettingsRow
          icon="server"
          iconColor={colors.accentMint}
          title="Signature Database"
          subtitle={`Last updated: ${signatureStats.lastUpdated}`}
        />
        <View style={styles.divider} />

        <View style={styles.dbStats}>
          <View style={styles.dbStatRow}>
            <Text style={styles.dbStatLabel}>Package Patterns</Text>
            <Text style={styles.dbStatValue}>{signatureStats.totalPackagePatterns}</Text>
          </View>
          <View style={styles.dbStatRow}>
            <Text style={styles.dbStatLabel}>C2 Domains</Text>
            <Text style={styles.dbStatValue}>{signatureStats.totalC2Domains}</Text>
          </View>
          <View style={styles.dbStatRow}>
            <Text style={styles.dbStatLabel}>Permission Combos</Text>
            <Text style={styles.dbStatValue}>{signatureStats.totalPermCombos}</Text>
          </View>
          <View style={styles.dbStatRow}>
            <Text style={styles.dbStatLabel}>Behavioral Rules</Text>
            <Text style={styles.dbStatValue}>{signatureStats.totalBehavioralRules}</Text>
          </View>
          <View style={styles.dbStatRow}>
            <Text style={styles.dbStatLabel}>YARA Rules</Text>
            <Text style={styles.dbStatValue}>{signatureStats.totalYaraRules}</Text>
          </View>
        </View>

        <TouchableOpacity style={styles.updateBtn}>
          <Ionicons name="cloud-download" size={16} color={colors.bgDeep} />
          <Text style={styles.updateBtnText}>Check for Updates</Text>
        </TouchableOpacity>
      </GlassCard>

      {/* ── AI Analysis ────────────────────────────────────── */}
      <Text style={styles.sectionLabel}>AI ANALYSIS</Text>
      <GlassCard>
        <SettingsRow
          icon="sparkles"
          iconColor={colors.accentWarning}
          title="Cloud AI Analysis"
          subtitle="Send anonymized findings to AI for enhanced threat intelligence"
          right={
            <Switch
              value={aiConfig?.consentGiven || false}
              onValueChange={handleAIConsent}
              trackColor={{ false: colors.bgSurface, true: colors.accentWarning + '60' }}
              thumbColor={aiConfig?.consentGiven ? colors.accentWarning : colors.textMuted}
            />
          }
        />

        {aiConfig?.consentGiven && (
          <>
            <View style={styles.divider} />
            <Text style={styles.aiDisclaimer}>
              Only permission names, severity levels, and generic descriptions are sent. No device IDs, personal data, or identifying information leaves your device.
            </Text>

            {AI_PROVIDERS.map((provider, idx) => {
              const keyField = `${provider.id}Key` as keyof AIConfig;
              const hasKey = !!(aiConfig as any)[keyField];
              return (
                <React.Fragment key={provider.id}>
                  <View style={styles.divider} />
                  <View style={styles.aiProviderSection}>
                    <View style={styles.aiProviderHeader}>
                      <View style={styles.aiProviderInfo}>
                        <Text style={styles.aiProviderName}>
                          {idx + 1}. {provider.name}
                        </Text>
                        <Text style={styles.aiProviderModel}>
                          {provider.model} · {provider.freeQuota}
                        </Text>
                      </View>
                      {hasKey && (
                        <View style={[styles.aiStatusDot, { backgroundColor: colors.accentSuccess }]} />
                      )}
                    </View>

                    <View style={styles.aiKeyRow}>
                      <TextInput
                        style={styles.aiKeyInput}
                        placeholder="Paste API key..."
                        placeholderTextColor={colors.textMuted}
                        value={aiKeyInputs[provider.id]}
                        onChangeText={(text) =>
                          setAiKeyInputs((prev) => ({ ...prev, [provider.id]: text }))
                        }
                        secureTextEntry
                        autoCapitalize="none"
                        autoCorrect={false}
                      />
                    </View>

                    <View style={styles.aiKeyActions}>
                      <TouchableOpacity
                        style={styles.aiKeyBtn}
                        onPress={() => handleSaveKey(provider.id)}
                      >
                        <Text style={styles.aiKeyBtnText}>Save</Text>
                      </TouchableOpacity>

                      <TouchableOpacity
                        style={styles.aiKeyBtn}
                        onPress={() => handleTestProvider(provider.id)}
                        disabled={testingProvider === provider.id}
                      >
                        {testingProvider === provider.id ? (
                          <ActivityIndicator size="small" color={colors.accentInfo} />
                        ) : (
                          <Text style={[styles.aiKeyBtnText, { color: colors.accentInfo }]}>Test</Text>
                        )}
                      </TouchableOpacity>

                      <TouchableOpacity
                        style={styles.aiKeyBtn}
                        onPress={() => Linking.openURL(provider.keyUrl)}
                      >
                        <Text style={[styles.aiKeyBtnText, { color: colors.accentMint }]}>Get Key</Text>
                      </TouchableOpacity>
                    </View>
                  </View>
                </React.Fragment>
              );
            })}
          </>
        )}
      </GlassCard>

      {/* ── Offline AI Model ─────────────────────────────── */}
      <Text style={styles.sectionLabel}>ON-DEVICE AI (OFFLINE)</Text>
      <GlassCard>
        <View style={styles.settingsRow}>
          <View style={[styles.settingsIcon, { backgroundColor: colors.accentOrange + '20' }]}>
            <Ionicons name="hardware-chip" size={18} color={colors.accentOrange} />
          </View>
          <View style={styles.settingsText}>
            <Text style={styles.settingsTitle}>Offline AI Analysis</Text>
            <Text style={styles.settingsSubtitle}>Run AI on-device without internet</Text>
          </View>
          <Switch
            value={offlineConfig.enabled}
            onValueChange={handleOfflineToggle}
            trackColor={{ false: colors.bgSurface, true: colors.accentOrange + '50' }}
            thumbColor={offlineConfig.enabled ? colors.accentOrange : colors.textMuted}
          />
        </View>

        {offlineConfig.enabled && (
          <>
            <View style={styles.divider} />

            {/* Resource Info */}
            <View style={styles.offlineInfoBlock}>
              <Text style={styles.offlineInfoTitle}>Device Requirements</Text>
              <View style={styles.offlineInfoGrid}>
                <View style={styles.offlineInfoRow}>
                  <Ionicons name="cloud-download" size={14} color={colors.textMuted} />
                  <Text style={styles.offlineInfoLabel}>Download:</Text>
                  <Text style={styles.offlineInfoValue}>{RESOURCE_REQUIREMENTS.downloadSize}</Text>
                </View>
                <View style={styles.offlineInfoRow}>
                  <Ionicons name="folder" size={14} color={colors.textMuted} />
                  <Text style={styles.offlineInfoLabel}>Storage:</Text>
                  <Text style={styles.offlineInfoValue}>{RESOURCE_REQUIREMENTS.storageRequired}</Text>
                </View>
                <View style={styles.offlineInfoRow}>
                  <Ionicons name="speedometer" size={14} color={colors.textMuted} />
                  <Text style={styles.offlineInfoLabel}>RAM:</Text>
                  <Text style={styles.offlineInfoValue}>{RESOURCE_REQUIREMENTS.ramDuringInference}</Text>
                </View>
                <View style={styles.offlineInfoRow}>
                  <Ionicons name="flash" size={14} color={colors.textMuted} />
                  <Text style={styles.offlineInfoLabel}>CPU:</Text>
                  <Text style={styles.offlineInfoValue}>{RESOURCE_REQUIREMENTS.cpuUsage}</Text>
                </View>
                <View style={styles.offlineInfoRow}>
                  <Ionicons name="battery-half" size={14} color={colors.textMuted} />
                  <Text style={styles.offlineInfoLabel}>Battery:</Text>
                  <Text style={styles.offlineInfoValue}>{RESOURCE_REQUIREMENTS.batteryImpact}</Text>
                </View>
              </View>
              <Text style={styles.offlineInfoNote}>{RESOURCE_REQUIREMENTS.note}</Text>
            </View>

            <View style={styles.divider} />

            {/* Model Status */}
            <View style={styles.offlineStatusBlock}>
              <Text style={styles.offlineInfoTitle}>Model Status</Text>
              <View style={styles.offlineInfoRow}>
                <Ionicons
                  name={offlineConfig.modelDownloaded ? 'checkmark-circle' : 'close-circle'}
                  size={16}
                  color={offlineConfig.modelDownloaded ? colors.accentSuccess : colors.accentDanger}
                />
                <Text style={[styles.offlineStatusText, {
                  color: offlineConfig.modelDownloaded ? colors.accentSuccess : colors.accentDanger
                }]}>
                  {offlineConfig.modelDownloaded ? 'Ready' : 'Not Downloaded'}
                </Text>
                {offlineStorageUsed > 0 && (
                  <Text style={styles.offlineStorageText}>
                    ({(offlineStorageUsed / 1_000_000_000).toFixed(1)} GB used)
                  </Text>
                )}
              </View>
              <Text style={styles.offlineModelName}>
                {OFFLINE_MODEL_INFO.name} · {OFFLINE_MODEL_INFO.quantization} · {OFFLINE_MODEL_INFO.parameters}
              </Text>
            </View>

            {/* Download Progress */}
            {offlineDownloading && (
              <>
                <View style={styles.divider} />
                <View style={styles.offlineProgressBlock}>
                  <View style={styles.offlineProgressHeader}>
                    <ActivityIndicator size="small" color={colors.accentOrange} />
                    <Text style={styles.offlineProgressText}>Downloading... {offlineProgress}%</Text>
                  </View>
                  <View style={styles.offlineProgressTrack}>
                    <View style={[styles.offlineProgressFill, { width: `${offlineProgress}%` }]} />
                  </View>
                  <Text style={styles.offlineProgressHint}>
                    Keep the app open. Wi-Fi recommended.
                  </Text>
                </View>
              </>
            )}

            {/* Action Buttons */}
            <View style={styles.divider} />
            <View style={styles.offlineActions}>
              {!offlineConfig.modelDownloaded && !offlineDownloading && (
                <TouchableOpacity style={styles.offlineActionBtn} onPress={handleDownloadModel}>
                  <Ionicons name="cloud-download" size={16} color={colors.accentOrange} />
                  <Text style={[styles.offlineActionText, { color: colors.accentOrange }]}>Download Model</Text>
                </TouchableOpacity>
              )}
              {offlineConfig.modelDownloaded && (
                <TouchableOpacity style={styles.offlineActionBtn} onPress={handleDeleteModel}>
                  <Ionicons name="trash" size={16} color={colors.accentDanger} />
                  <Text style={[styles.offlineActionText, { color: colors.accentDanger }]}>Delete Model</Text>
                </TouchableOpacity>
              )}
            </View>
          </>
        )}
      </GlassCard>

      {/* ── Language ─────────────────────────────────────── */}
      <Text style={styles.sectionLabel}>LANGUAGE</Text>
      <GlassCard>
        {AVAILABLE_LANGUAGES.map((lang, idx) => (
          <React.Fragment key={lang.code}>
            {idx > 0 && <View style={styles.divider} />}
            <TouchableOpacity
              onPress={() => handleLanguageChange(lang.code)}
              style={styles.langRow}
            >
              <Text style={styles.langFlag}>{lang.flag}</Text>
              <Text style={styles.langLabel}>{lang.label}</Text>
              <Ionicons
                name={currentLang === lang.code ? 'radio-button-on' : 'radio-button-off'}
                size={20}
                color={currentLang === lang.code ? colors.accentMint : colors.textMuted}
              />
            </TouchableOpacity>
          </React.Fragment>
        ))}
      </GlassCard>

      {/* ── Data & Privacy ────────────────────────────────── */}
      <Text style={styles.sectionLabel}>DATA & PRIVACY</Text>
      <GlassCard>
        <SettingsRow
          icon="shield-checkmark"
          iconColor={colors.accentSuccess}
          title="100% Local Processing"
          subtitle="All scans run on-device. No data is ever transmitted."
        />
        <View style={styles.divider} />
        <SettingsRow
          icon="document-text"
          iconColor={colors.accentInfo}
          title="Export Reports"
          subtitle="Share scan reports as text, HTML, or JSON"
        />
        <View style={styles.divider} />
        <TouchableOpacity onPress={handleClearHistory}>
          <SettingsRow
            icon="trash"
            iconColor={colors.accentDanger}
            title="Clear Scan History"
            subtitle={`${historyStats?.totalScans ?? 0} scans stored locally`}
            right={<Ionicons name="chevron-forward" size={16} color={colors.textMuted} />}
          />
        </TouchableOpacity>
      </GlassCard>

      {/* ── About ─────────────────────────────────────────── */}
      <Text style={styles.sectionLabel}>ABOUT</Text>
      <GlassCard>
        <View style={styles.aboutSection}>
          <Ionicons name="shield-checkmark" size={36} color={colors.accentMint} />
          <Text style={styles.aboutTitle}>ShieldScan</Text>
          <Text style={styles.aboutVersion}>Version 1.0.0</Text>
          <Text style={styles.aboutDesc}>
            Mobile security scanner with 8 AI agents.{'\n'}
            Built for privacy — everything runs locally.
          </Text>
        </View>
      </GlassCard>

      <View style={{ height: 80 }} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgDeep },
  content: { paddingHorizontal: layout.screenPaddingH, paddingTop: 40 },

  headerTitle: { fontSize: 28, fontWeight: '700', color: colors.textPrimary, marginBottom: 8, letterSpacing: -0.5 },
  headerSub: { fontSize: 15, color: colors.textSecondary, lineHeight: 22, marginBottom: 24 },

  sectionLabel: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted, letterSpacing: 1.5, marginTop: 24, marginBottom: 10 },

  settingsRow: { flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 12 },
  settingsIcon: { width: 36, height: 36, borderRadius: 10, alignItems: 'center', justifyContent: 'center' },
  settingsText: { flex: 1, gap: 2 },
  settingsTitle: { fontSize: 15, fontWeight: '600', color: colors.textPrimary },
  settingsSubtitle: { fontSize: 12, color: colors.textSecondary },
  settingsRight: { marginLeft: 8 },

  divider: { height: 1, backgroundColor: colors.glassBorder, marginVertical: 4 },

  freqLabel: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted, letterSpacing: 1, marginTop: 12, marginBottom: 10 },
  freqGrid: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  freqPill: { paddingHorizontal: 14, paddingVertical: 7, borderRadius: borderRadius.full, borderWidth: 1, borderColor: colors.glassBorder },
  freqPillActive: { backgroundColor: colors.accentMint + '20', borderColor: colors.accentMint + '50' },
  freqPillText: { fontSize: 13, fontWeight: '600', color: colors.textSecondary },
  freqPillTextActive: { color: colors.accentMint },
  freqDesc: { fontSize: 12, color: colors.textMuted, marginTop: 8, fontStyle: 'italic' },

  statsGrid: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'space-between' },
  statBox: { width: '48%', alignItems: 'center', paddingVertical: 14 },
  statValue: { fontSize: 24, fontWeight: '700', color: colors.textPrimary, fontFamily: 'monospace' },
  statLabel: { fontSize: 11, color: colors.textSecondary, marginTop: 2 },

  dbStats: { gap: 8, marginVertical: 12 },
  dbStatRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  dbStatLabel: { fontSize: 13, color: colors.textSecondary },
  dbStatValue: { fontFamily: 'monospace', fontSize: 14, fontWeight: '700', color: colors.accentMint },

  updateBtn: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8, backgroundColor: colors.accentMint, paddingVertical: 12, borderRadius: borderRadius.md, marginTop: 8 },
  updateBtnText: { fontSize: 14, fontWeight: '600', color: colors.bgDeep },

  // AI Analysis
  aiDisclaimer: { fontSize: 11, color: colors.textMuted, fontStyle: 'italic', lineHeight: 16, paddingVertical: 8 },
  aiProviderSection: { paddingVertical: 8 },
  aiProviderHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
  aiProviderInfo: { flex: 1, gap: 2 },
  aiProviderName: { fontSize: 14, fontWeight: '600', color: colors.textPrimary },
  aiProviderModel: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted },
  aiStatusDot: { width: 8, height: 8, borderRadius: 4 },
  aiKeyRow: { marginBottom: 8 },
  aiKeyInput: { backgroundColor: colors.bgSurface, borderRadius: borderRadius.sm, paddingHorizontal: 12, paddingVertical: 8, fontSize: 13, color: colors.textPrimary, borderWidth: 1, borderColor: colors.glassBorder, fontFamily: 'monospace' },
  aiKeyActions: { flexDirection: 'row', gap: 8 },
  aiKeyBtn: { paddingHorizontal: 14, paddingVertical: 6, borderRadius: borderRadius.sm, backgroundColor: colors.bgSurface, borderWidth: 1, borderColor: colors.glassBorder, minWidth: 50, alignItems: 'center' },
  aiKeyBtnText: { fontSize: 12, fontWeight: '600', color: colors.accentWarning },

  // Offline AI
  offlineInfoBlock: { paddingVertical: 10, gap: 8 },
  offlineInfoTitle: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted, letterSpacing: 1.2, marginBottom: 4 },
  offlineInfoGrid: { gap: 6 },
  offlineInfoRow: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  offlineInfoLabel: { fontSize: 12, color: colors.textSecondary, width: 70 },
  offlineInfoValue: { fontSize: 12, color: colors.textPrimary, fontFamily: 'monospace', flex: 1 },
  offlineInfoNote: { fontSize: 11, color: colors.accentSuccess, lineHeight: 16, marginTop: 6, fontStyle: 'italic' },
  offlineStatusBlock: { paddingVertical: 10, gap: 6 },
  offlineStatusText: { fontSize: 13, fontWeight: '600' },
  offlineStorageText: { fontSize: 11, color: colors.textMuted, fontFamily: 'monospace' },
  offlineModelName: { fontSize: 11, color: colors.textMuted, fontFamily: 'monospace', marginTop: 2 },
  offlineProgressBlock: { paddingVertical: 10, gap: 8 },
  offlineProgressHeader: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  offlineProgressText: { fontSize: 13, fontWeight: '600', color: colors.accentOrange },
  offlineProgressTrack: { height: 6, borderRadius: 3, backgroundColor: colors.bgSurface, overflow: 'hidden' },
  offlineProgressFill: { height: '100%', borderRadius: 3, backgroundColor: colors.accentOrange },
  offlineProgressHint: { fontSize: 11, color: colors.textMuted, fontStyle: 'italic' },
  offlineActions: { flexDirection: 'row', gap: 10, paddingVertical: 8 },
  offlineActionBtn: { flexDirection: 'row', alignItems: 'center', gap: 6, paddingHorizontal: 14, paddingVertical: 8, borderRadius: borderRadius.sm, backgroundColor: colors.bgSurface, borderWidth: 1, borderColor: colors.glassBorder },
  offlineActionText: { fontSize: 12, fontWeight: '600' },

  langRow: { flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 12 },
  langFlag: { fontSize: 22 },
  langLabel: { flex: 1, fontSize: 15, fontWeight: '600', color: colors.textPrimary },

  aboutSection: { alignItems: 'center', paddingVertical: 20, gap: 8 },
  aboutTitle: { fontSize: 22, fontWeight: '700', color: colors.textPrimary },
  aboutVersion: { fontFamily: 'monospace', fontSize: 12, color: colors.textMuted },
  aboutDesc: { fontSize: 13, color: colors.textSecondary, textAlign: 'center', lineHeight: 19, marginTop: 4 },
});
