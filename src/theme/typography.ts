/**
 * ShieldScan Typography System
 * Using system fonts that match the web app's feel
 */

import { Platform } from 'react-native';

export const fonts = {
  // Space Grotesk equivalent — bold, techy headers
  heading: Platform.select({
    ios: 'System',
    android: 'sans-serif-medium',
    default: 'System',
  })!,

  // Inter equivalent — clean body text
  body: Platform.select({
    ios: 'System',
    android: 'sans-serif',
    default: 'System',
  })!,

  // Mono — data, stats, labels
  mono: Platform.select({
    ios: 'Menlo',
    android: 'monospace',
    default: 'monospace',
  })!,
};

export const fontSizes = {
  xs: 10,
  sm: 12,
  md: 14,
  base: 16,
  lg: 18,
  xl: 22,
  '2xl': 28,
  '3xl': 34,
  '4xl': 42,
} as const;

export const fontWeights = {
  normal: '400' as const,
  medium: '500' as const,
  semibold: '600' as const,
  bold: '700' as const,
};

export const lineHeights = {
  tight: 1.1,
  snug: 1.25,
  normal: 1.4,
  relaxed: 1.6,
};
