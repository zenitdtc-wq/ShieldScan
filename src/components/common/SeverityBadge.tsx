import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { colors } from '../../theme';
import type { SeverityLevel } from '../../types/engine';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  size?: 'sm' | 'md';
}

export default function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const color = colors.severity[severity] || colors.textMuted;
  const label = severity.charAt(0).toUpperCase() + severity.slice(1);

  return (
    <View
      style={[
        styles.badge,
        size === 'md' && styles.badgeMd,
        { backgroundColor: `${color}20`, borderColor: `${color}40` },
      ]}
    >
      <View style={[styles.dot, { backgroundColor: color }]} />
      <Text style={[styles.label, size === 'md' && styles.labelMd, { color }]}>
        {label}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 5,
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 999,
    borderWidth: 1,
  },
  badgeMd: {
    paddingHorizontal: 12,
    paddingVertical: 5,
  },
  dot: {
    width: 6,
    height: 6,
    borderRadius: 3,
  },
  label: {
    fontFamily: 'monospace',
    fontSize: 10,
    fontWeight: '600',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  labelMd: {
    fontSize: 12,
  },
});
