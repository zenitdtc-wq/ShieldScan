/**
 * ShieldScan Dark Cyber Theme — Color Palette
 * Ported from the web app CSS variables
 */

export const colors = {
  // Backgrounds
  bgDeep: '#02050A',
  bgSurface: '#0A1628',
  bgCard: '#0E1E35',
  bgGlass: 'rgba(14, 30, 53, 0.6)',
  bgElevated: '#132740',

  // Text
  textPrimary: '#E8ECF1',
  textSecondary: '#8A9BB5',
  textMuted: '#4A5F7A',

  // Accents
  accentMint: '#00F5D4',
  accentInfo: '#00A3FF',
  accentWarning: '#FFC107',
  accentDanger: '#FF3B5C',
  accentSuccess: '#00E676',
  accentOrange: '#FF8C00',

  // Module Colors
  modulePermissions: '#00A3FF',
  moduleBehavior: '#FFC107',
  moduleSignature: '#FF3B5C',
  moduleNetwork: '#00F5D4',
  moduleIntegrity: '#00E676',

  // Glass / Borders
  glassBorder: 'rgba(58, 74, 94, 0.4)',
  glassHighlight: 'rgba(255, 255, 255, 0.03)',

  // Severity mapped
  severity: {
    safe: '#00E676',
    low: '#00A3FF',
    medium: '#FFC107',
    high: '#FF8C00',
    critical: '#FF3B5C',
  } as Record<string, string>,

  // Ring track
  ringTrack: 'rgba(58, 74, 94, 0.3)',

  // Transparent overlays
  overlay: 'rgba(2, 5, 10, 0.7)',
  overlayLight: 'rgba(2, 5, 10, 0.4)',
} as const;
