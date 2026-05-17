import React, { useMemo } from 'react';
import { View, Text, FlatList, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, fonts, fontSizes, spacing, borderRadius, layout } from '../theme';
import GlassCard from '../components/common/GlassCard';
import SeverityBadge from '../components/common/SeverityBadge';
import { threatFamilies, getThreatStats } from '../data/threats';
import type { ThreatFamily } from '../types/engine';

const formatDate = (iso: string) => {
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
};

const GLOSSARY = [
  { term: 'Banking Trojan', def: 'Specialized trojan targeting financial apps with overlay attacks, SMS interception, or credential theft.' },
  { term: 'Stalkerware', def: 'Monitoring tools installed without consent, typically used for interpersonal surveillance.' },
  { term: 'RAT', def: 'Remote Access Trojan — provides full device control to an attacker including camera, mic, and files.' },
  { term: 'Credential Stealer', def: 'Malware that captures passwords, tokens, or recovery phrases through keylogging or screen capture.' },
  { term: 'Loader/Dropper', def: 'Initial-stage malware that downloads and installs additional malicious payloads after installation.' },
  { term: 'Commercial Spyware', def: 'Sophisticated surveillance tools sold to governments, exploiting zero-day vulnerabilities.' },
];

// ─── Stats Bar ──────────────────────────────────────────────────
function StatsBar() {
  const stats = getThreatStats();
  const items = [
    { label: 'Critical', count: stats.critical, color: colors.severity.critical },
    { label: 'High', count: stats.high, color: colors.severity.high },
    { label: 'Total', count: stats.total, color: colors.accentMint },
  ];

  return (
    <View style={styles.statsBar}>
      {items.map((item) => (
        <View key={item.label} style={styles.statChip}>
          <View style={[styles.statDotSmall, { backgroundColor: item.color }]} />
          <Text style={[styles.statCount, { color: item.color }]}>{item.count}</Text>
          <Text style={styles.statLabel}>{item.label}</Text>
        </View>
      ))}
    </View>
  );
}

// ─── Threat Card ────────────────────────────────────────────────
function ThreatCard({ threat }: { threat: ThreatFamily }) {
  const accentColor = colors.severity[threat.severity] || colors.textMuted;

  return (
    <GlassCard style={styles.threatCard} accentColor={accentColor}>
      {/* Header */}
      <View style={styles.threatHeader}>
        <View style={{ flex: 1, marginRight: 8 }}>
          <Text style={styles.threatName}>{threat.name}</Text>
          {threat.aliases.length > 0 && (
            <Text style={styles.threatAliases}>aka {threat.aliases.join(', ')}</Text>
          )}
        </View>
        <SeverityBadge severity={threat.severity} />
      </View>

      {/* Category */}
      <View style={[styles.categoryTag, { borderColor: accentColor + '40' }]}>
        <Ionicons name="pricetag" size={11} color={accentColor} />
        <Text style={[styles.categoryText, { color: accentColor }]}>{threat.category}</Text>
      </View>

      {/* Description */}
      <Text style={styles.threatDesc}>{threat.description}</Text>

      {/* Indicators */}
      <View style={styles.indicatorBox}>
        <Text style={styles.indicatorTitle}>INDICATORS</Text>
        {threat.indicators.slice(0, 4).map((ind, i) => (
          <View key={i} style={styles.indicatorRow}>
            <View style={[styles.indicatorDot, { backgroundColor: accentColor }]} />
            <Text style={styles.indicatorText} numberOfLines={1}>{ind}</Text>
          </View>
        ))}
      </View>

      {/* Footer */}
      <View style={styles.threatFooter}>
        <View style={styles.metaItem}>
          <Ionicons name="scan" size={12} color={colors.textMuted} />
          <Text style={styles.metaText}>{threat.detectionCount} detections</Text>
        </View>
        <View style={styles.metaItem}>
          <Ionicons name="calendar-outline" size={12} color={colors.textMuted} />
          <Text style={styles.metaText}>{formatDate(threat.firstSeen)}</Text>
        </View>
        <View style={styles.metaItem}>
          <Ionicons name="time-outline" size={12} color={colors.textMuted} />
          <Text style={styles.metaText}>{formatDate(threat.lastSeen)}</Text>
        </View>
      </View>
    </GlassCard>
  );
}

// ─── Main Screen ────────────────────────────────────────────────
export default function IntelScreen() {
  const sortedThreats = useMemo(() => {
    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, safe: 4 };
    return [...threatFamilies].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  }, []);

  return (
    <FlatList
      style={styles.root}
      data={sortedThreats}
      keyExtractor={(item) => item.id}
      contentContainerStyle={styles.listContent}
      showsVerticalScrollIndicator={false}
      ListHeaderComponent={
        <>
          <Text style={styles.headerTitle}>Threat Intelligence</Text>
          <Text style={styles.headerSub}>
            Known threat families detected by ShieldScan's YARA engine and behavioral heuristics.
          </Text>
          <StatsBar />
        </>
      }
      renderItem={({ item }) => <ThreatCard threat={item} />}
      ListFooterComponent={
        <View style={styles.glossarySection}>
          <Text style={styles.glossaryTitle}>Threat Categories</Text>
          <Text style={styles.glossarySub}>Common classification terms in mobile threat intelligence</Text>
          {GLOSSARY.map((entry) => (
            <View key={entry.term} style={styles.glossaryItem}>
              <Text style={styles.glossaryTerm}>{entry.term}</Text>
              <Text style={styles.glossaryDef}>{entry.def}</Text>
            </View>
          ))}
          <View style={{ height: 80 }} />
        </View>
      }
    />
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgDeep },
  listContent: { paddingHorizontal: layout.screenPaddingH, paddingTop: 40 },

  headerTitle: { fontSize: 28, fontWeight: '700', color: colors.textPrimary, marginBottom: 8 },
  headerSub: { fontSize: 14, color: colors.textSecondary, lineHeight: 20, marginBottom: 16 },

  statsBar: { flexDirection: 'row', backgroundColor: colors.bgSurface, borderRadius: borderRadius.lg, borderWidth: 1, borderColor: colors.glassBorder, padding: 12, marginBottom: 20, justifyContent: 'space-around' },
  statChip: { flexDirection: 'row', alignItems: 'center', gap: 4 },
  statDotSmall: { width: 8, height: 8, borderRadius: 4 },
  statCount: { fontFamily: 'monospace', fontSize: 18, fontWeight: '700' },
  statLabel: { fontSize: 12, color: colors.textSecondary },

  threatCard: { padding: 16, marginBottom: 12 },
  threatHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 },
  threatName: { fontSize: 18, fontWeight: '700', color: colors.textPrimary },
  threatAliases: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted, marginTop: 2 },

  categoryTag: { flexDirection: 'row', alignItems: 'center', gap: 4, borderWidth: 1, borderRadius: 6, paddingHorizontal: 8, paddingVertical: 3, alignSelf: 'flex-start', marginBottom: 10 },
  categoryText: { fontSize: 10, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 0.8 },

  threatDesc: { fontSize: 14, color: colors.textSecondary, lineHeight: 20, marginBottom: 12 },

  indicatorBox: { backgroundColor: colors.bgDeep, borderRadius: borderRadius.md, padding: 12, marginBottom: 12 },
  indicatorTitle: { fontFamily: 'monospace', fontSize: 9, color: colors.textMuted, letterSpacing: 1.5, marginBottom: 8 },
  indicatorRow: { flexDirection: 'row', alignItems: 'center', marginBottom: 4 },
  indicatorDot: { width: 5, height: 5, borderRadius: 3, marginRight: 8 },
  indicatorText: { fontFamily: 'monospace', fontSize: 11, color: colors.textSecondary, flex: 1 },

  threatFooter: { flexDirection: 'row', flexWrap: 'wrap', gap: 14 },
  metaItem: { flexDirection: 'row', alignItems: 'center', gap: 4 },
  metaText: { fontSize: 11, color: colors.textMuted },

  glossarySection: { marginTop: 32, paddingTop: 24, borderTopWidth: 1, borderTopColor: colors.glassBorder },
  glossaryTitle: { fontSize: 22, fontWeight: '700', color: colors.textPrimary, marginBottom: 4 },
  glossarySub: { fontSize: 14, color: colors.textSecondary, marginBottom: 20, lineHeight: 20 },
  glossaryItem: { marginBottom: 16, paddingLeft: 12, borderLeftWidth: 2, borderLeftColor: colors.accentInfo },
  glossaryTerm: { fontSize: 14, fontWeight: '600', color: colors.accentInfo, marginBottom: 2 },
  glossaryDef: { fontSize: 12, color: colors.textSecondary, lineHeight: 17 },
});
