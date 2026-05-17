import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, Switch, FlatList, Alert } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, fonts, layout, borderRadius } from '../theme';
import GlassCard from '../components/common/GlassCard';
import { toggleVpnMonitor, getNetworkConnections } from '../native/NativeBridge';
import type { NetworkConnection } from '../types/engine';

export default function NetworkMonitorScreen() {
  const [vpnEnabled, setVpnEnabled] = useState(false);
  const [connections, setConnections] = useState<NetworkConnection[]>([]);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (vpnEnabled) {
      interval = setInterval(async () => {
        const conns = await getNetworkConnections();
        setConnections(conns);
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [vpnEnabled]);

  const handleToggleVpn = async (value: boolean) => {
    try {
      const success = await toggleVpnMonitor(value);
      if (success) {
        setVpnEnabled(value);
      } else {
        Alert.alert('Error', 'Failed to toggle VPN Monitor.');
      }
    } catch (err: any) {
      if (err.message && err.message.includes('VPN_PERMISSION_REQUIRED')) {
        Alert.alert('Action Required', 'Please confirm the Android VPN permission dialog, then try again.');
      } else {
        Alert.alert('Error', 'An unexpected error occurred.');
      }
    }
  };

  const renderConnection = ({ item }: { item: NetworkConnection }) => {
    const isSuspicious = item.remotePort !== 443 && item.remotePort !== 80;
    const accentColor = isSuspicious ? colors.accentWarning : colors.accentInfo;

    return (
      <GlassCard style={styles.connCard} accentColor={accentColor}>
        <View style={styles.connHeader}>
          <Text style={styles.connPackage}>{item.packageName || 'Unknown App'}</Text>
          <Text style={[styles.connState, { color: accentColor }]}>{item.state}</Text>
        </View>
        <Text style={styles.connRemote}>
          {item.protocol} — {item.remoteAddress}:{item.remotePort}
        </Text>
        <Text style={styles.connLocal}>Local: {item.localPort}</Text>
      </GlassCard>
    );
  };

  return (
    <View style={styles.root}>
      <Text style={styles.headerTitle}>Network Monitor</Text>
      <Text style={styles.headerSub}>
        Inspects outbound traffic via a local sinkhole VPN to detect stalkerware C2 communication.
      </Text>

      <GlassCard style={styles.controlCard} accentColor={vpnEnabled ? colors.accentMint : colors.textMuted}>
        <View style={styles.row}>
          <View style={styles.textContainer}>
            <Text style={styles.title}>Traffic Interception</Text>
            <Text style={styles.description}>
              {vpnEnabled ? 'VPN Monitor is active. Scanning outbound traffic...' : 'VPN Monitor is offline.'}
            </Text>
          </View>
          <Switch
            value={vpnEnabled}
            onValueChange={handleToggleVpn}
            trackColor={{ false: colors.textMuted, true: colors.accentMint }}
            thumbColor="#fff"
          />
        </View>
      </GlassCard>

      {vpnEnabled && (
        <FlatList
          data={connections}
          keyExtractor={(item, index) => `${item.remoteAddress}-${item.localPort}-${index}`}
          renderItem={renderConnection}
          contentContainerStyle={styles.listContent}
          showsVerticalScrollIndicator={false}
          ListEmptyComponent={
            <Text style={styles.emptyText}>No active connections intercepted yet.</Text>
          }
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgDeep, padding: layout.screenPaddingH, paddingTop: 40 },
  headerTitle: { fontSize: 24, fontWeight: '700', color: colors.textPrimary, marginBottom: 8 },
  headerSub: { fontSize: 14, color: colors.textSecondary, marginBottom: 24, lineHeight: 20 },
  controlCard: { padding: 16, marginBottom: 24 },
  row: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  textContainer: { flex: 1, paddingRight: 16 },
  title: { fontSize: 16, fontWeight: '600', color: colors.textPrimary, marginBottom: 4 },
  description: { fontSize: 13, color: colors.textSecondary, lineHeight: 18 },
  listContent: { paddingBottom: 40 },
  connCard: { padding: 12, marginBottom: 12 },
  connHeader: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 6 },
  connPackage: { fontSize: 14, fontWeight: '600', color: colors.textPrimary },
  connState: { fontSize: 10, fontWeight: '700', letterSpacing: 0.5 },
  connRemote: { fontSize: 13, color: colors.textSecondary, fontFamily: 'monospace', marginBottom: 2 },
  connLocal: { fontSize: 11, color: colors.textMuted, fontFamily: 'monospace' },
  emptyText: { textAlign: 'center', color: colors.textMuted, marginTop: 40, fontStyle: 'italic' }
});
