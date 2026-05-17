import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import Svg, { Circle } from 'react-native-svg';
import { colors } from '../../theme';

interface ProgressRingProps {
  progress: number; // 0-100
  size?: number;
  strokeWidth?: number;
  color?: string;
  showLabel?: boolean;
  label?: string;
}

export default function ProgressRing({
  progress,
  size = 120,
  strokeWidth = 8,
  color,
  showLabel = true,
  label,
}: ProgressRingProps) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (progress / 100) * circumference;

  const progressColor =
    color ||
    (progress > 75
      ? colors.accentDanger
      : progress > 50
      ? colors.accentWarning
      : colors.accentSuccess);

  return (
    <View style={[styles.container, { width: size, height: size }]}>
      <Svg width={size} height={size} style={styles.svg}>
        {/* Track */}
        <Circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={colors.ringTrack}
          strokeWidth={strokeWidth}
          fill="none"
        />
        {/* Progress */}
        <Circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={progressColor}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          fill="none"
          strokeDasharray={`${circumference}`}
          strokeDashoffset={strokeDashoffset}
          rotation={-90}
          origin={`${size / 2}, ${size / 2}`}
        />
      </Svg>
      {showLabel && (
        <View style={styles.labelContainer}>
          <Text style={[styles.value, { color: progressColor }]}>{Math.round(progress)}</Text>
          <Text style={styles.sublabel}>{label || '/ 100'}</Text>
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    alignItems: 'center',
    justifyContent: 'center',
  },
  svg: {
    position: 'absolute',
  },
  labelContainer: {
    alignItems: 'center',
  },
  value: {
    fontSize: 28,
    fontWeight: '700',
    letterSpacing: -1,
  },
  sublabel: {
    fontFamily: 'monospace',
    fontSize: 9,
    color: colors.textSecondary,
    textTransform: 'uppercase',
    letterSpacing: 1,
  },
});
