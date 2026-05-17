/**
 * ShieldScan — Forensic Log Screen
 *
 * Evidence chain viewer for investigation by authorities.
 * Features:
 * - Category filter bar (All, Threats, Connections, Apps, System)
 * - Expandable event cards with full evidence
 * - Export buttons (JSON, CSV, Report)
 * - "Share with Authorities" via native Share API
 * - SHA-256 integrity hash display
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  TouchableOpacity,
  Alert,
  Share,
  ActivityIndicator,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, layout } from '../theme';
import GlassCard from '../components/common/GlassCard';
import {
  getForensicLog,
  exportForensicLog,
  clearForensicLog,
  getForensicStats,
  type ForensicEntry,
  type ForensicCategory,
} from '../utils/forensicLog';

type FilterCategory = 'all' | ForensicCategory;

const FILTERS: { id: FilterCategory; label: string; icon: keyof typeof Ionicons.glyphMap }[] = [
  { id: 'all', label: 'All', icon: 'list' },
  { id: 'threat', label: 'Threats', icon: 'warning' },
  { id: 'connection', label: 'Connections', icon: 'globe' },
  { id: 'app', label: 'Apps', icon: 'apps' },
  { id: 'system', label: 'System', icon: 'hardware-chip' },
];

// ─── Log Entry Card ─────────────────────────────────────────────

function LogEntryCard({ entry }: { entry: ForensicEntry }) {
  const [expanded, setExpanded] = useState(false);

  const sevColor =
    entry.severity === 'critical' ? colors.accentDanger :
    entry.severity === 'warning' ? colors.accentWarning : colors.accentInfo;

  const catIcon: keyof typeof Ionicons.glyphMap =
    entry.category === 'threat' ? 'warning' :
    entry.category === 'connection' ? 'globe' :
    entry.category === 'app' ? 'apps' : 'hardware-chip';

  const timeStr = new Date(entry.timestamp).toLocaleString();

  return (
    <TouchableOpacity
      onPress={() => setExpanded(!expanded)}
      activeOpacity={0.8}
    >
      <GlassCard style={styles.logCard} accentColor={sevColor}>
        <View style={styles.logHeader}>
          <View style={[styles.logCatIcon, { backgroundColor: sevColor + '18' }]}>
            <Ionicons name={catIcon} size={16} color={sevColor} />
          </View>
          <View style={styles.logMeta}>
            <Text style={styles.logTitle} numberOfLines={expanded ? undefined : 1}>
              {entry.title}
            </Text>
            <Text style={styles.logTime}>{timeStr}</Text>
          </View>
          <View style={[styles.logSevBadge, { backgroundColor: sevColor + '20' }]}>
            <Text style={[styles.logSevText, { color: sevColor }]}>
              {entry.severity.toUpperCase()}
            </Text>
          </View>
        </View>

        {expanded && (
          <View style={styles.logExpanded}>
            <Text style={styles.logDetail}>{entry.detail}</Text>

            {entry.evidence.length > 0 && (
              <View style={styles.logSection}>
                <Text style={styles.logSectionLabel}>EVIDENCE</Text>
                {entry.evidence.map((ev, i) => (
                  <View key={i} style={styles.evidenceRow}>
                    <View style={styles.evidenceDot} />
                    <Text style={styles.evidenceText}>{ev}</Text>
                  </View>
                ))}
              </View>
            )}

            <View style={styles.logFooter}>
              {entry.sourceModule && (
                <Text style={styles.logFooterText}>Module: {entry.sourceModule}</Text>
              )}
              {entry.packageName && (
                <Text style={styles.logFooterText}>Package: {entry.packageName}</Text>
              )}
              {entry.remoteAddress && (
                <Text style={styles.logFooterText}>Remote: {entry.remoteAddress}</Text>
              )}
            </View>
          </View>
        )}
      </GlassCard>
    </TouchableOpacity>
  );
}

// ─── Main Screen ────────────────────────────────────────────────

export default function ForensicLogScreen() {
  const [entries, setEntries] = useState<ForensicEntry[]>([]);
  const [filter, setFilter] = useState<FilterCategory>('all');
  const [stats, setStats] = useState<any>(null);
  const [exporting, setExporting] = useState(false);
  const [integrityHash, setIntegrityHash] = useState('');

  const loadLog = useCallback(async () => {
    const log = await getForensicLog();
    setEntries(log);
    const s = await getForensicStats();
    setStats(s);

    // Compute integrity hash
    if (log.length > 0) {
      const { integrityHash: hash } = await exportForensicLog('json');
      setIntegrityHash(hash);
    }
  }, []);

  useEffect(() => {
    loadLog();
  }, [loadLog]);

  const filtered = filter === 'all'
    ? entries
    : entries.filter((e) => e.category === filter);

  const handleExport = useCallback(async (format: 'json' | 'csv' | 'txt') => {
    try {
      setExporting(true);
      const { content } = await exportForensicLog(format);
      await Share.share({
        message: content,
        title: `ShieldScan Forensic Report (${format.toUpperCase()})`,
      });
    } catch (err) {
      Alert.alert('Export Failed', 'Unable to export forensic log.');
    } finally {
      setExporting(false);
    }
  }, []);

  const handleShareAuthorities = useCallback(async () => {
    try {
      setExporting(true);
      const { content, integrityHash: hash } = await exportForensicLog('txt');
      await Share.share({
        message: content,
        title: 'ShieldScan Forensic Evidence Report',
      });
    } catch (err) {
      Alert.alert('Share Failed', 'Unable to share report.');
    } finally {
      setExporting(false);
    }
  }, []);

  const handleClear = useCallback(() => {
    Alert.alert(
      'Clear Forensic Log',
      'This will permanently delete all forensic log entries. This cannot be undone.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Clear',
          style: 'destructive',
          onPress: async () => {
            await clearForensicLog();
            await loadLog();
          },
        },
      ],
    );
  }, [loadLog]);

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      {/* Header */}
      <Text style={styles.headerTitle}>Forensic Log</Text>
      <Text style={styles.headerSub}>Evidence chain for investigation.</Text>

      {/* Export Actions */}
      <View style={styles.exportRow}>
        <TouchableOpacity
          style={styles.exportBtn}
          onPress={() => handleExport('json')}
          disabled={exporting}
        >
          <Ionicons name="code-slash" size={14} color={colors.accentMint} />
          <Text style={styles.exportBtnText}>Export JSON</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.exportBtn}
          onPress={() => handleExport('csv')}
          disabled={exporting}
        >
          <Ionicons name="grid" size={14} color={colors.accentInfo} />
          <Text style={[styles.exportBtnText, { color: colors.accentInfo }]}>Export CSV</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.exportBtn}
          onPress={() => handleExport('txt')}
          disabled={exporting}
        >
          <Ionicons name="document-text" size={14} color={colors.accentWarning} />
          <Text style={[styles.exportBtnText, { color: colors.accentWarning }]}>Export Report</Text>
        </TouchableOpacity>
      </View>

      {/* Share with Authorities */}
      <TouchableOpacity
        style={styles.shareAuthBtn}
        onPress={handleShareAuthorities}
        disabled={exporting || entries.length === 0}
      >
        <Ionicons name="shield" size={16} color={colors.bgDeep} />
        <Text style={styles.shareAuthText}>Share with Authorities</Text>
      </TouchableOpacity>

      {exporting && (
        <View style={styles.exportingRow}>
          <ActivityIndicator size="small" color={colors.accentMint} />
          <Text style={styles.exportingText}>Preparing export...</Text>
        </View>
      )}

      {/* Integrity Hash */}
      {integrityHash ? (
        <GlassCard style={styles.integrityCard}>
          <View style={styles.integrityHeader}>
            <Ionicons name="finger-print" size={16} color={colors.accentSuccess} />
            <Text style={styles.integrityLabel}>Log Integrity</Text>
          </View>
          <Text style={styles.integrityHash}>{integrityHash}</Text>
          <Text style={styles.integrityMeta}>
            {stats?.totalEntries || 0} entries
            {stats?.dateRange ? ` · ${stats.dateRange.from} — ${stats.dateRange.to}` : ''}
          </Text>
        </GlassCard>
      ) : null}

      {/* Filter Bar */}
      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        style={styles.filterScroll}
        contentContainerStyle={styles.filterContent}
      >
        {FILTERS.map((f) => {
          const isActive = filter === f.id;
          return (
            <TouchableOpacity
              key={f.id}
              style={[styles.filterPill, isActive && styles.filterPillActive]}
              onPress={() => setFilter(f.id)}
            >
              <Ionicons
                name={f.icon}
                size={14}
                color={isActive ? colors.accentMint : colors.textMuted}
              />
              <Text
                style={[
                  styles.filterText,
                  isActive && styles.filterTextActive,
                ]}
              >
                {f.label}
              </Text>
            </TouchableOpacity>
          );
        })}
      </ScrollView>

      {/* Log Entries */}
      {filtered.length === 0 ? (
        <GlassCard>
          <Text style={styles.emptyText}>
            No forensic log entries{filter !== 'all' ? ` in "${filter}" category` : ''}. Run a scan to populate.
          </Text>
        </GlassCard>
      ) : (
        <View style={styles.logList}>
          {filtered.map((entry) => (
            <LogEntryCard key={entry.id} entry={entry} />
          ))}
        </View>
      )}

      {/* Clear Log */}
      {entries.length > 0 && (
        <TouchableOpacity style={styles.clearBtn} onPress={handleClear}>
          <Ionicons name="trash-outline" size={16} color={colors.accentDanger} />
          <Text style={styles.clearBtnText}>Clear Log</Text>
        </TouchableOpacity>
      )}

      <View style={{ height: 80 }} />
    </ScrollView>
  );
}

// ─── Styles ─────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgDeep },
  content: { paddingHorizontal: layout.screenPaddingH, paddingTop: 40 },

  headerTitle: { fontSize: 28, fontWeight: '700', color: colors.textPrimary, marginBottom: 8, letterSpacing: -0.5 },
  headerSub: { fontSize: 15, color: colors.textSecondary, lineHeight: 22, marginBottom: 20 },

  // Export
  exportRow: { flexDirection: 'row', gap: 8, marginBottom: 12 },
  exportBtn: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    paddingVertical: 10,
    borderRadius: borderRadius.md,
    backgroundColor: colors.bgGlass,
    borderWidth: 1,
    borderColor: colors.glassBorder,
  },
  exportBtnText: { fontSize: 10, fontWeight: '600', color: colors.accentMint },

  shareAuthBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    backgroundColor: colors.accentMint,
    paddingVertical: 12,
    borderRadius: borderRadius.md,
    marginBottom: 16,
  },
  shareAuthText: { fontSize: 14, fontWeight: '600', color: colors.bgDeep },

  exportingRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: 12 },
  exportingText: { fontSize: 12, color: colors.textMuted, fontStyle: 'italic' },

  // Integrity
  integrityCard: { padding: 16, marginBottom: 16 },
  integrityHeader: { flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 8 },
  integrityLabel: { fontSize: 14, fontWeight: '600', color: colors.accentSuccess },
  integrityHash: { fontFamily: 'monospace', fontSize: 10, color: colors.textSecondary, marginBottom: 4 },
  integrityMeta: { fontSize: 11, color: colors.textMuted },

  // Filter
  filterScroll: { marginBottom: 16 },
  filterContent: { flexDirection: 'row', gap: 8 },
  filterPill: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 14,
    paddingVertical: 7,
    borderRadius: borderRadius.full,
    borderWidth: 1,
    borderColor: colors.glassBorder,
  },
  filterPillActive: {
    backgroundColor: colors.accentMint + '20',
    borderColor: colors.accentMint + '50',
  },
  filterText: { fontSize: 12, fontWeight: '600', color: colors.textSecondary },
  filterTextActive: { color: colors.accentMint },

  // Log
  logList: { gap: 10 },
  logCard: { padding: 14 },
  logHeader: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  logCatIcon: { width: 32, height: 32, borderRadius: 8, alignItems: 'center', justifyContent: 'center' },
  logMeta: { flex: 1, gap: 2 },
  logTitle: { fontSize: 13, fontWeight: '600', color: colors.textPrimary },
  logTime: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted },
  logSevBadge: { paddingHorizontal: 8, paddingVertical: 3, borderRadius: borderRadius.full },
  logSevText: { fontFamily: 'monospace', fontSize: 9, fontWeight: '700' },

  logExpanded: { marginTop: 12, paddingTop: 12, borderTopWidth: 1, borderTopColor: colors.glassBorder, gap: 10 },
  logDetail: { fontSize: 13, color: colors.textSecondary, lineHeight: 18 },
  logSection: { gap: 4 },
  logSectionLabel: { fontFamily: 'monospace', fontSize: 9, color: colors.textMuted, letterSpacing: 1.5 },
  evidenceRow: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  evidenceDot: { width: 4, height: 4, borderRadius: 2, backgroundColor: colors.textMuted },
  evidenceText: { fontFamily: 'monospace', fontSize: 11, color: colors.textSecondary },
  logFooter: { gap: 2 },
  logFooterText: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted },

  // Empty
  emptyText: { fontSize: 13, color: colors.textMuted, textAlign: 'center', paddingVertical: 16 },

  // Clear
  clearBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    paddingVertical: 12,
    marginTop: 24,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.accentDanger + '40',
  },
  clearBtnText: { fontSize: 14, fontWeight: '600', color: colors.accentDanger },
});
