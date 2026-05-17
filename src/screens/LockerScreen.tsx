import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, TouchableOpacity, Alert } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import * as LocalAuthentication from 'expo-local-authentication';
import { colors, fonts, spacing, borderRadius, layout } from '../theme';
import GlassCard from '../components/common/GlassCard';
import { triggerIntruderTrap } from '../utils/intruderTrap';

export default function LockerScreen() {
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [hasBiometrics, setHasBiometrics] = useState(false);

  useEffect(() => {
    (async () => {
      const compatible = await LocalAuthentication.hasHardwareAsync();
      const enrolled = await LocalAuthentication.isEnrolledAsync();
      setHasBiometrics(compatible && enrolled);
    })();
  }, []);

  const handleAuthenticate = async () => {
    try {
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Authenticate to access ShieldScan Vault',
        fallbackLabel: 'Use Passcode',
        disableDeviceFallback: false,
      });

      if (result.success) {
        setIsUnlocked(true);
        setFailedAttempts(0);
      } else {
        const newFails = failedAttempts + 1;
        setFailedAttempts(newFails);
        
        if (newFails >= 3) {
          await triggerIntruderTrap(newFails);
          Alert.alert('Security Alert', 'Intruder Trap activated. This event has been logged.');
        } else {
          Alert.alert('Authentication Failed', `Attempt ${newFails} of 3 before lockdown.`);
        }
      }
    } catch (err) {
      console.warn(err);
    }
  };

  if (isUnlocked) {
    return (
      <View style={styles.root}>
        <Text style={styles.headerTitle}>Secure Vault</Text>
        <GlassCard style={styles.card} accentColor={colors.accentSuccess}>
          <Ionicons name="lock-open" size={32} color={colors.accentSuccess} style={{ marginBottom: 16 }} />
          <Text style={styles.title}>Vault Unlocked</Text>
          <Text style={styles.description}>You can now manage your locked apps and sensitive forensic data.</Text>
          
          <TouchableOpacity style={styles.lockButton} onPress={() => setIsUnlocked(false)}>
            <Text style={styles.lockButtonText}>Lock Vault Now</Text>
          </TouchableOpacity>
        </GlassCard>
      </View>
    );
  }

  return (
    <View style={styles.lockedRoot}>
      <Ionicons name="shield-half" size={80} color={colors.accentMint} style={{ marginBottom: 24 }} />
      <Text style={styles.lockedTitle}>ShieldScan Vault</Text>
      <Text style={styles.lockedSub}>Protected by Biometric Security</Text>

      <TouchableOpacity style={styles.authButton} onPress={handleAuthenticate}>
        <Ionicons name={hasBiometrics ? 'finger-print' : 'keypad'} size={24} color={colors.bgDeep} />
        <Text style={styles.authButtonText}>Tap to Unlock</Text>
      </TouchableOpacity>

      {failedAttempts > 0 && (
        <Text style={styles.warningText}>
          Failed attempts: {failedAttempts}/3
        </Text>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgDeep, padding: layout.screenPaddingH, paddingTop: 40 },
  headerTitle: { fontSize: 24, fontWeight: '700', color: colors.textPrimary, marginBottom: 24 },
  card: { padding: 24, alignItems: 'center' },
  title: { fontSize: 18, fontWeight: '700', color: colors.textPrimary, marginBottom: 8 },
  description: { fontSize: 14, color: colors.textSecondary, textAlign: 'center', lineHeight: 20 },
  lockButton: { marginTop: 24, backgroundColor: 'rgba(255,255,255,0.1)', paddingVertical: 12, paddingHorizontal: 24, borderRadius: borderRadius.full },
  lockButtonText: { color: colors.textPrimary, fontWeight: '600' },

  lockedRoot: { flex: 1, backgroundColor: colors.bgDeep, justifyContent: 'center', alignItems: 'center', padding: 24 },
  lockedTitle: { fontSize: 28, fontWeight: '700', color: colors.textPrimary, marginBottom: 8 },
  lockedSub: { fontSize: 14, color: colors.textSecondary, marginBottom: 40 },
  authButton: { flexDirection: 'row', alignItems: 'center', backgroundColor: colors.accentMint, paddingVertical: 14, paddingHorizontal: 32, borderRadius: borderRadius.full, gap: 12 },
  authButtonText: { fontSize: 16, fontWeight: '700', color: colors.bgDeep },
  warningText: { marginTop: 24, color: colors.accentDanger, fontSize: 14, fontWeight: '600' }
});
