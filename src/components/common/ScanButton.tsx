import React from 'react';
import { TouchableOpacity, Text, StyleSheet, ActivityIndicator, View } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, borderRadius } from '../../theme';

interface ScanButtonProps {
  onPress: () => void;
  isScanning?: boolean;
  isComplete?: boolean;
  disabled?: boolean;
  label?: string;
}

export default function ScanButton({
  onPress,
  isScanning = false,
  isComplete = false,
  disabled = false,
  label,
}: ScanButtonProps) {
  const buttonLabel = label || (isComplete ? 'Scan Again' : isScanning ? 'Scanning...' : 'Start Scan Now');

  return (
    <TouchableOpacity
      onPress={onPress}
      disabled={disabled || isScanning}
      style={[
        styles.button,
        isComplete && styles.buttonOutline,
        (disabled || isScanning) && styles.buttonDisabled,
      ]}
      activeOpacity={0.85}
    >
      <View style={styles.inner}>
        {isScanning ? (
          <ActivityIndicator size="small" color={colors.bgDeep} />
        ) : (
          <Ionicons
            name={isComplete ? 'refresh' : 'shield-checkmark'}
            size={20}
            color={isComplete ? colors.accentMint : colors.bgDeep}
          />
        )}
        <Text
          style={[
            styles.label,
            isComplete && styles.labelOutline,
          ]}
        >
          {buttonLabel}
        </Text>
      </View>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  button: {
    backgroundColor: colors.accentMint,
    borderRadius: borderRadius.full,
    paddingVertical: 16,
    paddingHorizontal: 40,
    shadowColor: colors.accentMint,
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.3,
    shadowRadius: 20,
    elevation: 8,
  },
  buttonOutline: {
    backgroundColor: 'transparent',
    borderWidth: 2,
    borderColor: colors.accentMint,
  },
  buttonDisabled: {
    opacity: 0.6,
  },
  inner: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
  },
  label: {
    fontSize: 16,
    fontWeight: '700',
    color: colors.bgDeep,
    letterSpacing: -0.3,
  },
  labelOutline: {
    color: colors.accentMint,
  },
});
