import React from 'react';
import { View, StyleSheet, ViewStyle, StyleProp } from 'react-native';
import { colors } from '../../theme';

interface GlassCardProps {
  children: React.ReactNode;
  style?: StyleProp<ViewStyle>;
  interactive?: boolean;
  accentColor?: string;
}

export default function GlassCard({
  children,
  style,
  interactive = false,
  accentColor,
}: GlassCardProps) {
  return (
    <View
      style={[
        styles.card,
        interactive && styles.interactive,
        accentColor && { borderLeftWidth: 3, borderLeftColor: accentColor },
        style,
      ]}
    >
      {children}
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.bgGlass,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: colors.glassBorder,
    padding: 16,
    overflow: 'hidden',
  },
  interactive: {
    backgroundColor: colors.bgCard,
  },
});
