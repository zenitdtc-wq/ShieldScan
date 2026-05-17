import React, { useState } from 'react';
import { View, Text, Switch, StyleSheet, Alert, TouchableOpacity } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, fonts, spacing, borderRadius, layout } from '../theme';
import GlassCard from '../components/common/GlassCard';
import { toggleGhostMode } from '../native/NativeBridge';

export default function GhostModeSettings() {
  const [ghostModeEnabled, setGhostModeEnabled] = useState(false);
  const [panicButtonEnabled, setPanicButtonEnabled] = useState(true);

  const handleToggleGhostMode = async (value: boolean) => {
    try {
      const success = await toggleGhostMode(value);
      if (success) {
        setGhostModeEnabled(value);
        Alert.alert(
          'Ghost Mode ' + (value ? 'Enabled' : 'Disabled'),
          value ? 'The app icon and name will now appear as "Calculator". The app may restart to apply changes.' : 'The app icon has been restored to ShieldScan.'
        );
      } else {
        Alert.alert('Error', 'Failed to toggle Ghost Mode. Ensure native modules are linked.');
      }
    } catch (err) {
      Alert.alert('Error', 'An unexpected error occurred.');
    }
  };

  return (
    <View style={styles.root}>
      <Text style={styles.headerTitle}>Victim Safety Protocols</Text>
      <Text style={styles.headerSub}>
        These features are designed to protect you if an abuser has physical access to your device.
      </Text>

      <GlassCard style={styles.card} accentColor={colors.accentWarning}>
        <View style={styles.row}>
          <View style={styles.textContainer}>
            <Text style={styles.title}>Ghost Mode (Camouflage)</Text>
            <Text style={styles.description}>
              Hides ShieldScan by changing its app icon and name to "Calculator" on your home screen and app drawer.
            </Text>
          </View>
          <Switch
            value={ghostModeEnabled}
            onValueChange={handleToggleGhostMode}
            trackColor={{ false: colors.textMuted, true: colors.accentWarning }}
            thumbColor="#fff"
          />
        </View>
      </GlassCard>

      <GlassCard style={styles.card} accentColor={colors.accentDanger}>
        <View style={styles.row}>
          <View style={styles.textContainer}>
            <Text style={styles.title}>Panic Button</Text>
            <Text style={styles.description}>
              Shows a floating Panic Button. Tapping it instantly closes the app and replaces your screen with a benign website.
            </Text>
          </View>
          <Switch
            value={panicButtonEnabled}
            onValueChange={setPanicButtonEnabled}
            trackColor={{ false: colors.textMuted, true: colors.accentDanger }}
            thumbColor="#fff"
          />
        </View>
      </GlassCard>

      <View style={styles.infoBox}>
        <Ionicons name="shield-checkmark" size={24} color={colors.accentSuccess} />
        <Text style={styles.infoText}>
          If you believe you are in immediate physical danger, prioritizing your safety is more important than scanning for stalkerware. Please contact local authorities or domestic violence support services.
        </Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgDeep, padding: layout.screenPaddingH, paddingTop: 40 },
  headerTitle: { fontSize: 24, fontWeight: '700', color: colors.textPrimary, marginBottom: 8 },
  headerSub: { fontSize: 14, color: colors.textSecondary, marginBottom: 24, lineHeight: 20 },
  card: { padding: 16, marginBottom: 16 },
  row: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  textContainer: { flex: 1, paddingRight: 16 },
  title: { fontSize: 16, fontWeight: '600', color: colors.textPrimary, marginBottom: 4 },
  description: { fontSize: 13, color: colors.textSecondary, lineHeight: 18 },
  infoBox: { flexDirection: 'row', alignItems: 'center', backgroundColor: colors.bgSurface, padding: 16, borderRadius: borderRadius.md, borderWidth: 1, borderColor: colors.glassBorder, marginTop: 16 },
  infoText: { flex: 1, fontSize: 12, color: colors.textSecondary, marginLeft: 12, lineHeight: 18 },
});
