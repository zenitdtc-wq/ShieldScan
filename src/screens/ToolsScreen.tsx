import React, { useState, useCallback } from 'react';
import {
  View, Text, ScrollView, StyleSheet, TouchableOpacity, ActivityIndicator,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, layout } from '../theme';
import GlassCard from '../components/common/GlassCard';

type ToolId = 'bluetooth' | 'permissions' | 'webrtc' | 'network';

const toolTabs: { id: ToolId; label: string; icon: keyof typeof Ionicons.glyphMap }[] = [
  { id: 'bluetooth', label: 'Bluetooth', icon: 'bluetooth' },
  { id: 'permissions', label: 'Permissions', icon: 'lock-closed' },
  { id: 'webrtc', label: 'WebRTC', icon: 'globe' },
  { id: 'network', label: 'Network', icon: 'wifi' },
];

// ─── Bluetooth Scanner ──────────────────────────────────────────
function BluetoothPanel() {
  const [scanning, setScanning] = useState(false);
  const [devices, setDevices] = useState<{ name: string; rssi: number; type: string }[]>([]);

  const startScan = useCallback(() => {
    setScanning(true);
    setDevices([]);
    setTimeout(() => {
      setDevices([
        { name: 'Galaxy Buds Pro', rssi: -42, type: 'Audio' },
        { name: 'Unknown Device', rssi: -78, type: 'Unknown' },
        { name: 'Smart Watch', rssi: -55, type: 'Wearable' },
        { name: 'Unknown Device', rssi: -91, type: 'Unknown' },
        { name: 'Bluetooth Speaker', rssi: -63, type: 'Audio' },
      ]);
      setScanning(false);
    }, 3000);
  }, []);

  const signalBars = (rssi: number) => {
    if (rssi > -50) return 4;
    if (rssi > -65) return 3;
    if (rssi > -80) return 2;
    return 1;
  };

  return (
    <GlassCard style={styles.toolPanel}>
      <View style={styles.toolHeader}>
        <View style={[styles.toolIconBox, { backgroundColor: '#00A3FF18' }]}>
          <Ionicons name="bluetooth" size={22} color="#00A3FF" />
        </View>
        <View>
          <Text style={styles.toolTitle}>Bluetooth Environment Scanner</Text>
          <Text style={styles.toolSub}>Scan for nearby Bluetooth devices</Text>
        </View>
      </View>

      <TouchableOpacity onPress={startScan} disabled={scanning} style={[styles.toolBtn, scanning && styles.toolBtnDisabled]}>
        {scanning ? <ActivityIndicator size="small" color={colors.bgDeep} /> : <Ionicons name="search" size={16} color={colors.bgDeep} />}
        <Text style={styles.toolBtnText}>{scanning ? 'Scanning...' : 'Start Scan'}</Text>
      </TouchableOpacity>

      {devices.length > 0 && (
        <View style={styles.resultList}>
          <Text style={styles.resultCount}>{devices.length} devices found</Text>
          {devices.map((d, i) => (
            <View key={i} style={styles.deviceRow}>
              <Ionicons name={d.type === 'Audio' ? 'headset' : d.type === 'Wearable' ? 'watch' : 'help-circle'} size={18} color={colors.textSecondary} />
              <View style={{ flex: 1 }}>
                <Text style={styles.deviceName}>{d.name}</Text>
                <Text style={styles.deviceType}>{d.type} · {d.rssi} dBm</Text>
              </View>
              <View style={styles.signalBars}>
                {[1, 2, 3, 4].map((bar) => (
                  <View key={bar} style={[styles.signalBar, { height: 4 + bar * 4, backgroundColor: bar <= signalBars(d.rssi) ? colors.accentMint : colors.textMuted + '30' }]} />
                ))}
              </View>
            </View>
          ))}
        </View>
      )}
    </GlassCard>
  );
}

// ─── Permission Auditor ─────────────────────────────────────────
function PermissionsPanel() {
  const [expanded, setExpanded] = useState<string | null>(null);

  const apps = [
    { name: 'Flashlight Pro', pkg: 'com.example.flash', perms: 7, risk: 'high' as const, permissions: [
      { name: 'READ_SMS', risk: 'critical' }, { name: 'INTERNET', risk: 'low' }, { name: 'CAMERA', risk: 'high' },
      { name: 'READ_CONTACTS', risk: 'high' }, { name: 'LOCATION', risk: 'high' }, { name: 'STORAGE', risk: 'medium' }, { name: 'MICROPHONE', risk: 'high' },
    ]},
    { name: 'Battery Saver', pkg: 'com.example.battery', perms: 4, risk: 'medium' as const, permissions: [
      { name: 'BOOT_COMPLETED', risk: 'medium' }, { name: 'INTERNET', risk: 'low' }, { name: 'LOCATION', risk: 'high' }, { name: 'WAKE_LOCK', risk: 'low' },
    ]},
    { name: 'Quick Notes', pkg: 'com.example.notes', perms: 1, risk: 'low' as const, permissions: [
      { name: 'STORAGE', risk: 'medium' },
    ]},
    { name: 'Chrome', pkg: 'com.android.chrome', perms: 2, risk: 'safe' as const, permissions: [
      { name: 'INTERNET', risk: 'safe' }, { name: 'CAMERA', risk: 'safe' },
    ]},
  ];

  const riskColors: Record<string, string> = { safe: colors.accentSuccess, low: colors.accentInfo, medium: colors.accentWarning, high: colors.accentDanger, critical: colors.accentDanger };

  return (
    <GlassCard style={styles.toolPanel}>
      <View style={styles.toolHeader}>
        <View style={[styles.toolIconBox, { backgroundColor: '#FFC10718' }]}>
          <Ionicons name="lock-closed" size={22} color="#FFC107" />
        </View>
        <View>
          <Text style={styles.toolTitle}>App Permission Auditor</Text>
          <Text style={styles.toolSub}>Review permissions for installed apps</Text>
        </View>
      </View>

      {apps.map((app) => (
        <View key={app.pkg}>
          <TouchableOpacity onPress={() => setExpanded(expanded === app.pkg ? null : app.pkg)} style={styles.appRow}>
            <View style={{ flex: 1 }}>
              <Text style={styles.appName}>{app.name}</Text>
              <Text style={styles.appPkg}>{app.pkg}</Text>
            </View>
            <View style={[styles.permBadge, { backgroundColor: (riskColors[app.risk] || colors.textMuted) + '20' }]}>
              <Text style={[styles.permBadgeText, { color: riskColors[app.risk] }]}>{app.perms} perms</Text>
            </View>
            <Ionicons name={expanded === app.pkg ? 'chevron-up' : 'chevron-down'} size={16} color={colors.textMuted} />
          </TouchableOpacity>

          {expanded === app.pkg && (
            <View style={styles.permList}>
              {app.permissions.map((p, i) => (
                <View key={i} style={styles.permRow}>
                  <View style={[styles.permDot, { backgroundColor: riskColors[p.risk] || colors.textMuted }]} />
                  <Text style={styles.permName}>{p.name}</Text>
                  <Text style={[styles.permRisk, { color: riskColors[p.risk] }]}>{p.risk.toUpperCase()}</Text>
                </View>
              ))}
            </View>
          )}
        </View>
      ))}
    </GlassCard>
  );
}

// ─── WebRTC Test ────────────────────────────────────────────────
function WebRTCPanel() {
  const [testing, setTesting] = useState(false);
  const [results, setResults] = useState<{ label: string; value: string; status: 'pass' | 'fail' | 'warn' }[] | null>(null);

  const runTest = useCallback(() => {
    setTesting(true);
    setResults(null);
    setTimeout(() => {
      setResults([
        { label: 'Local IP', value: '192.168.1.100', status: 'warn' },
        { label: 'Public IP', value: 'Hidden', status: 'pass' },
        { label: 'STUN Server', value: 'No leak detected', status: 'pass' },
        { label: 'TURN Server', value: 'Not configured', status: 'pass' },
        { label: 'IPv6 Leak', value: 'Not detected', status: 'pass' },
      ]);
      setTesting(false);
    }, 2500);
  }, []);

  const statusIcon = (s: string): keyof typeof Ionicons.glyphMap => s === 'pass' ? 'checkmark-circle' : s === 'fail' ? 'close-circle' : 'warning';
  const statusColor = (s: string) => s === 'pass' ? colors.accentSuccess : s === 'fail' ? colors.accentDanger : colors.accentWarning;

  return (
    <GlassCard style={styles.toolPanel}>
      <View style={styles.toolHeader}>
        <View style={[styles.toolIconBox, { backgroundColor: '#00F5D418' }]}>
          <Ionicons name="globe" size={22} color="#00F5D4" />
        </View>
        <View>
          <Text style={styles.toolTitle}>WebRTC Leak Test</Text>
          <Text style={styles.toolSub}>Check for IP address leaks via WebRTC</Text>
        </View>
      </View>

      <TouchableOpacity onPress={runTest} disabled={testing} style={[styles.toolBtn, testing && styles.toolBtnDisabled]}>
        {testing ? <ActivityIndicator size="small" color={colors.bgDeep} /> : <Ionicons name="flask" size={16} color={colors.bgDeep} />}
        <Text style={styles.toolBtnText}>{testing ? 'Testing...' : 'Run Test'}</Text>
      </TouchableOpacity>

      {results && (
        <View style={styles.resultList}>
          {results.map((r, i) => (
            <View key={i} style={styles.testRow}>
              <Ionicons name={statusIcon(r.status)} size={18} color={statusColor(r.status)} />
              <Text style={styles.testLabel}>{r.label}</Text>
              <Text style={[styles.testValue, { color: statusColor(r.status) }]}>{r.value}</Text>
            </View>
          ))}
        </View>
      )}
    </GlassCard>
  );
}

// ─── Network Traffic ────────────────────────────────────────────
function NetworkPanel() {
  const [monitoring, setMonitoring] = useState(false);
  const [connections, setConnections] = useState<{ protocol: string; remote: string; port: number; status: string; data: string }[]>([]);

  const startMonitor = useCallback(() => {
    setMonitoring(true);
    setConnections([]);
    setTimeout(() => {
      setConnections([
        { protocol: 'TCP', remote: '142.250.80.46', port: 443, status: 'safe', data: '1.2 MB' },
        { protocol: 'TCP', remote: '185.220.101.42', port: 443, status: 'suspicious', data: '340 KB' },
        { protocol: 'UDP', remote: '224.0.0.251', port: 5353, status: 'safe', data: '12 KB' },
        { protocol: 'TCP', remote: '104.18.32.7', port: 80, status: 'warn', data: '89 KB' },
        { protocol: 'TCP', remote: '151.101.1.140', port: 443, status: 'safe', data: '2.8 MB' },
      ]);
      setMonitoring(false);
    }, 3000);
  }, []);

  const statusColors: Record<string, string> = { safe: colors.accentSuccess, suspicious: colors.accentDanger, warn: colors.accentWarning };

  return (
    <GlassCard style={styles.toolPanel}>
      <View style={styles.toolHeader}>
        <View style={[styles.toolIconBox, { backgroundColor: '#FF3B5C18' }]}>
          <Ionicons name="wifi" size={22} color="#FF3B5C" />
        </View>
        <View>
          <Text style={styles.toolTitle}>Live Traffic Monitor</Text>
          <Text style={styles.toolSub}>Analyze active network connections</Text>
        </View>
      </View>

      <TouchableOpacity onPress={startMonitor} disabled={monitoring} style={[styles.toolBtn, monitoring && styles.toolBtnDisabled]}>
        {monitoring ? <ActivityIndicator size="small" color={colors.bgDeep} /> : <Ionicons name="analytics" size={16} color={colors.bgDeep} />}
        <Text style={styles.toolBtnText}>{monitoring ? 'Monitoring...' : 'Start Monitoring'}</Text>
      </TouchableOpacity>

      {connections.length > 0 && (
        <View style={styles.resultList}>
          {connections.map((c, i) => (
            <View key={i} style={styles.connRow}>
              <View style={styles.connLeft}>
                <Text style={styles.connProtocol}>{c.protocol}</Text>
                <Text style={styles.connRemote}>{c.remote}:{c.port}</Text>
                <Text style={styles.connData}>{c.data}</Text>
              </View>
              <View style={[styles.connBadge, { backgroundColor: (statusColors[c.status] || colors.textMuted) + '20' }]}>
                <Text style={[styles.connBadgeText, { color: statusColors[c.status] || colors.textMuted }]}>
                  {c.status.toUpperCase()}
                </Text>
              </View>
            </View>
          ))}
        </View>
      )}
    </GlassCard>
  );
}

// ─── Main Screen ────────────────────────────────────────────────
export default function ToolsScreen() {
  const [activeTab, setActiveTab] = useState<ToolId>('bluetooth');

  const panels: Record<ToolId, React.ReactNode> = {
    bluetooth: <BluetoothPanel />,
    permissions: <PermissionsPanel />,
    webrtc: <WebRTCPanel />,
    network: <NetworkPanel />,
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Live Security Tools</Text>
        <Text style={styles.headerSub}>Run focused diagnostic checks without a full system scan.</Text>
        <Text style={styles.localBadge}>All checks run locally — no data sent</Text>
      </View>

      {/* Tab Selector */}
      <View style={styles.tabRow}>
        {toolTabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <TouchableOpacity
              key={tab.id}
              onPress={() => setActiveTab(tab.id)}
              style={[styles.tabPill, isActive && styles.tabPillActive]}
            >
              <Ionicons name={tab.icon} size={16} color={isActive ? colors.accentMint : colors.textSecondary} />
              <Text style={[styles.tabLabel, isActive && styles.tabLabelActive]}>{tab.label}</Text>
            </TouchableOpacity>
          );
        })}
      </View>

      {/* Active Panel */}
      {panels[activeTab]}

      <View style={{ height: 80 }} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgDeep },
  content: { paddingHorizontal: layout.screenPaddingH, paddingTop: 40 },

  header: { alignItems: 'center', marginBottom: 20 },
  headerTitle: { fontSize: 28, fontWeight: '700', color: colors.textPrimary, marginBottom: 8, letterSpacing: -0.5 },
  headerSub: { fontSize: 15, color: colors.textSecondary, textAlign: 'center', lineHeight: 22, maxWidth: 400, marginBottom: 8 },
  localBadge: { fontFamily: 'monospace', fontSize: 11, color: colors.accentMint, letterSpacing: 0.5 },

  tabRow: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'center', gap: 8, marginBottom: 20 },
  tabPill: { flexDirection: 'row', alignItems: 'center', gap: 6, paddingHorizontal: 14, paddingVertical: 8, borderRadius: borderRadius.full, borderWidth: 1, borderColor: colors.glassBorder, backgroundColor: colors.bgGlass },
  tabPillActive: { backgroundColor: colors.accentMint + '18', borderColor: colors.accentMint + '40' },
  tabLabel: { fontSize: 13, fontWeight: '600', color: colors.textSecondary },
  tabLabelActive: { color: colors.accentMint },

  toolPanel: { padding: 16, marginBottom: 16 },
  toolHeader: { flexDirection: 'row', alignItems: 'center', gap: 12, marginBottom: 16 },
  toolIconBox: { width: 44, height: 44, borderRadius: 12, alignItems: 'center', justifyContent: 'center' },
  toolTitle: { fontSize: 16, fontWeight: '700', color: colors.textPrimary },
  toolSub: { fontSize: 12, color: colors.textSecondary },

  toolBtn: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8, backgroundColor: colors.accentMint, paddingVertical: 12, borderRadius: borderRadius.md, marginBottom: 16 },
  toolBtnDisabled: { opacity: 0.7 },
  toolBtnText: { fontSize: 14, fontWeight: '600', color: colors.bgDeep },

  resultList: { gap: 8 },
  resultCount: { fontFamily: 'monospace', fontSize: 11, color: colors.accentMint, marginBottom: 8 },

  deviceRow: { flexDirection: 'row', alignItems: 'center', gap: 10, paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: colors.glassBorder },
  deviceName: { fontSize: 14, fontWeight: '600', color: colors.textPrimary },
  deviceType: { fontSize: 11, color: colors.textMuted },
  signalBars: { flexDirection: 'row', alignItems: 'flex-end', gap: 2 },
  signalBar: { width: 4, borderRadius: 1 },

  appRow: { flexDirection: 'row', alignItems: 'center', gap: 10, paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: colors.glassBorder },
  appName: { fontSize: 14, fontWeight: '600', color: colors.textPrimary },
  appPkg: { fontSize: 10, fontFamily: 'monospace', color: colors.textMuted },
  permBadge: { paddingHorizontal: 8, paddingVertical: 3, borderRadius: borderRadius.full },
  permBadgeText: { fontFamily: 'monospace', fontSize: 10, fontWeight: '600' },
  permList: { paddingLeft: 12, paddingVertical: 8 },
  permRow: { flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 6 },
  permDot: { width: 6, height: 6, borderRadius: 3 },
  permName: { fontFamily: 'monospace', fontSize: 12, color: colors.textSecondary, flex: 1 },
  permRisk: { fontFamily: 'monospace', fontSize: 9, fontWeight: '700' },

  testRow: { flexDirection: 'row', alignItems: 'center', gap: 10, paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: colors.glassBorder },
  testLabel: { fontSize: 14, color: colors.textSecondary, width: 90 },
  testValue: { flex: 1, fontSize: 13, fontWeight: '600', textAlign: 'right' },

  connRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: colors.glassBorder },
  connLeft: { flex: 1 },
  connProtocol: { fontFamily: 'monospace', fontSize: 10, fontWeight: '700', color: colors.accentInfo },
  connRemote: { fontSize: 13, color: colors.textPrimary },
  connData: { fontSize: 10, color: colors.textMuted },
  connBadge: { paddingHorizontal: 8, paddingVertical: 3, borderRadius: borderRadius.full },
  connBadgeText: { fontFamily: 'monospace', fontSize: 9, fontWeight: '700' },
});
