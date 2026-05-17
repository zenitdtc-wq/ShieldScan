import React from 'react';
import { View, Text, ScrollView, StyleSheet, Dimensions } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../types/navigation';
import { colors, fonts, fontSizes, fontWeights, spacing, borderRadius, layout } from '../theme';
import GlassCard from '../components/common/GlassCard';
import ScanButton from '../components/common/ScanButton';

const { width: SCREEN_WIDTH } = Dimensions.get('window');

const MODULES = [
  { icon: 'lock-closed' as const, color: '#00A3FF', title: 'Permission Analysis', description: 'Audits every granted permission and flags dangerous access patterns.' },
  { icon: 'pulse' as const, color: '#FFC107', title: 'Behavioral Heuristics', description: 'Detects background anomalies, covert data exfiltration, and battery drain.' },
  { icon: 'flash' as const, color: '#FF3B5C', title: 'YARA Signature', description: 'Matches installed apps against known malware signatures and threat families.' },
  { icon: 'globe' as const, color: '#00F5D4', title: 'Network Profiling', description: 'Analyzes DNS queries, open ports, and C2 beacon connections.' },
  { icon: 'shield-checkmark' as const, color: '#00E676', title: 'System Integrity', description: 'Checks bootloader, root status, encryption, and OS patch levels.' },
  { icon: 'eye' as const, color: '#E040FB', title: 'Adware & Stalkerware', description: 'Detects hidden surveillance apps, GPS trackers, and aggressive ad SDKs.' },
  { icon: 'cloud-upload' as const, color: '#FF6E40', title: 'Data Exfiltration', description: 'Identifies clipboard harvesting, contact scraping, and covert data theft.' },
  { icon: 'diamond' as const, color: '#64FFDA', title: 'Cryptojacking & Fraud', description: 'Detects crypto mining, premium SMS fraud, and subscription scams.' },
];

const STEPS = [
  { num: '1', label: 'Analyze', sub: 'Run 8 AI agents across your device' },
  { num: '2', label: 'Score', sub: 'Calculate a composite risk score 0-100' },
  { num: '3', label: 'Report', sub: 'Get detailed findings with evidence' },
  { num: '4', label: 'Clean', sub: 'Follow guided remediation steps' },
];

const TRUST_STATS = [
  { value: '0', label: 'Data Sent' },
  { value: '100%', label: 'Private' },
  { value: '8', label: 'AI Agents' },
  { value: '8', label: 'Threat Families' },
];

export default function HomeScreen() {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const cardWidth = (SCREEN_WIDTH - layout.screenPaddingH * 2 - spacing.md) / 2;

  return (
    <>
    <ScrollView
      style={styles.root}
      contentContainerStyle={styles.scrollContent}
      showsVerticalScrollIndicator={false}
    >
      {/* ── Hero ───────────────────────────────────────────── */}
      <View style={styles.heroSection}>
        <View style={styles.heroIconWrap}>
          <Ionicons name="shield-checkmark" size={64} color={colors.accentMint} />
        </View>

        <Text style={styles.heroHeadline}>
          Scan Your Smartphone{'\n'}Like a Security Analyst
        </Text>
        <Text style={styles.heroSub}>
          5 specialized modules running entirely on-device.{'\n'}
          No cloud. No telemetry. Just answers.
        </Text>

        <View style={styles.scanBtnWrap}>
          <ScanButton label="Run Full Security Scan" onPress={() => navigation.navigate('Scanner')} />
        </View>
      </View>

      {/* ── Module Grid ────────────────────────────────────── */}
      <Text style={styles.sectionTitle}>Scan Modules</Text>
      <Text style={styles.sectionSub}>Each module targets a unique attack surface</Text>

      <View style={styles.moduleGrid}>
        {MODULES.map((mod, idx) => (
          <GlassCard
            key={mod.title}
            style={[styles.moduleCard, { width: idx === MODULES.length - 1 ? '100%' : cardWidth }]}
          >
            <View style={[styles.moduleIconCircle, { backgroundColor: mod.color + '18' }]}>
              <Ionicons name={mod.icon} size={24} color={mod.color} />
            </View>
            <Text style={styles.moduleTitle}>{mod.title}</Text>
            <Text style={styles.moduleDesc}>{mod.description}</Text>
          </GlassCard>
        ))}
      </View>

      {/* ── How It Works ───────────────────────────────────── */}
      <Text style={[styles.sectionTitle, { marginTop: 32 }]}>How It Works</Text>

      <View style={styles.stepsContainer}>
        {STEPS.map((step, idx) => (
          <View key={step.label} style={styles.stepRow}>
            <View style={styles.stepNumWrap}>
              <View style={styles.stepCircle}>
                <Text style={styles.stepNum}>{step.num}</Text>
              </View>
              {idx < STEPS.length - 1 && <View style={styles.stepLine} />}
            </View>
            <View style={styles.stepTextWrap}>
              <Text style={styles.stepLabel}>{step.label}</Text>
              <Text style={styles.stepSub}>{step.sub}</Text>
            </View>
          </View>
        ))}
      </View>

      {/* ── Trust Panel ────────────────────────────────────── */}
      <Text style={[styles.sectionTitle, { marginTop: 32 }]}>Built for Trust</Text>
      <Text style={styles.sectionSub}>Everything happens on your device — nothing leaves.</Text>

      <GlassCard style={styles.trustCard}>
        <View style={styles.trustGrid}>
          {TRUST_STATS.map((stat) => (
            <View key={stat.label} style={styles.trustItem}>
              <Text style={styles.trustValue}>{stat.value}</Text>
              <Text style={styles.trustLabel}>{stat.label}</Text>
            </View>
          ))}
        </View>
      </GlassCard>

      {/* ── Privacy Badges ─────────────────────────────────── */}
      <View style={styles.badgeRow}>
        {['No Server Calls', 'Zero Data Stored', '100% Local'].map((label) => (
          <View key={label} style={styles.badge}>
            <Ionicons name="checkmark-circle" size={12} color={colors.accentSuccess} />
            <Text style={styles.badgeText}>{label}</Text>
          </View>
        ))}
      </View>

      {/* ── Bottom CTA ─────────────────────────────────────── */}
      <View style={styles.bottomCta}>
        <Text style={styles.bottomCtaLabel}>Ready to scan?</Text>
        <ScanButton label="Run Full Security Scan" onPress={() => navigation.navigate('Scanner')} />
      </View>

      <View style={{ height: 80 }} />
    </ScrollView>
    
    {/* AI Agent FAB */}
    <TouchableOpacity
      style={styles.fab}
      onPress={() => navigation.navigate('AiAgentScreen')}
      activeOpacity={0.8}
    >
      <View style={styles.fabIconWrap}>
        <Ionicons name="hardware-chip" size={24} color={colors.bgDeep} />
      </View>
    </TouchableOpacity>
    </>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgDeep },
  scrollContent: { paddingHorizontal: layout.screenPaddingH, paddingTop: 40, paddingBottom: 40 },

  heroSection: { alignItems: 'center', marginBottom: 40 },
  heroIconWrap: { width: 120, height: 120, borderRadius: 60, backgroundColor: 'rgba(0,245,212,0.05)', borderWidth: 1, borderColor: 'rgba(0,245,212,0.19)', alignItems: 'center', justifyContent: 'center', marginBottom: 24 },
  heroHeadline: { fontFamily: fonts.heading, fontSize: 32, fontWeight: '700', color: colors.textPrimary, textAlign: 'center', lineHeight: 37, marginBottom: 12 },
  heroSub: { fontFamily: fonts.body, fontSize: 15, color: colors.textSecondary, textAlign: 'center', lineHeight: 22, marginBottom: 24, paddingHorizontal: 16 },
  scanBtnWrap: { alignItems: 'center' },

  sectionTitle: { fontFamily: fonts.heading, fontSize: 22, fontWeight: '700', color: colors.textPrimary, marginBottom: 4 },
  sectionSub: { fontFamily: fonts.body, fontSize: 14, color: colors.textSecondary, marginBottom: 16, lineHeight: 20 },

  moduleGrid: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'space-between', gap: spacing.md },
  moduleCard: { padding: 16 },
  moduleIconCircle: { width: 44, height: 44, borderRadius: borderRadius.md, alignItems: 'center', justifyContent: 'center', marginBottom: 12 },
  moduleTitle: { fontSize: 14, fontWeight: '600', color: colors.textPrimary, marginBottom: 4 },
  moduleDesc: { fontSize: 12, color: colors.textSecondary, lineHeight: 17 },

  stepsContainer: { paddingLeft: 8, marginBottom: 20 },
  stepRow: { flexDirection: 'row', alignItems: 'flex-start' },
  stepNumWrap: { alignItems: 'center', marginRight: 16 },
  stepCircle: { width: 36, height: 36, borderRadius: 18, backgroundColor: 'rgba(0,245,212,0.09)', borderWidth: 1, borderColor: 'rgba(0,245,212,0.31)', alignItems: 'center', justifyContent: 'center' },
  stepNum: { fontFamily: 'monospace', fontSize: 14, fontWeight: '700', color: colors.accentMint },
  stepLine: { width: 2, height: 32, backgroundColor: colors.glassBorder },
  stepTextWrap: { flex: 1, paddingTop: 4, paddingBottom: 20 },
  stepLabel: { fontSize: 16, fontWeight: '600', color: colors.textPrimary, marginBottom: 2 },
  stepSub: { fontSize: 13, color: colors.textSecondary, lineHeight: 18 },

  trustCard: { padding: 24 },
  trustGrid: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'space-between' },
  trustItem: { width: '48%', alignItems: 'center', paddingVertical: 12 },
  trustValue: { fontFamily: 'monospace', fontSize: 28, fontWeight: '700', color: colors.accentMint, marginBottom: 4 },
  trustLabel: { fontSize: 12, color: colors.textSecondary },

  badgeRow: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'center', gap: 10, marginTop: 20 },
  badge: { flexDirection: 'row', alignItems: 'center', gap: 6, paddingHorizontal: 12, paddingVertical: 6, borderRadius: borderRadius.full, backgroundColor: 'rgba(0,230,118,0.08)', borderWidth: 1, borderColor: 'rgba(0,230,118,0.15)' },
  badgeText: { fontFamily: 'monospace', fontSize: 11, color: colors.accentSuccess },

  bottomCta: { alignItems: 'center', marginTop: 40, gap: 12 },
  bottomCtaLabel: { fontSize: 14, fontWeight: '500', color: colors.textSecondary },

  fab: {
    position: 'absolute',
    bottom: 24,
    right: 24,
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: colors.accentMint,
    alignItems: 'center',
    justifyContent: 'center',
    shadowColor: colors.accentMint,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.4,
    shadowRadius: 8,
    elevation: 8,
  },
  fabIconWrap: {
    alignItems: 'center',
    justifyContent: 'center',
  },
});
