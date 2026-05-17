import React, { useEffect, useRef } from 'react';
import { NavigationContainer, DefaultTheme, NavigationContainerRef } from '@react-navigation/native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import AppNavigator from './navigation/AppNavigator';
import { colors } from './theme';
import { requestNotificationPermissions, addNotificationResponseListener } from './utils/notifications';
import { initLanguage } from './i18n';
import type { RootTabParamList } from './types/navigation';

const ShieldScanTheme = {
  ...DefaultTheme,
  dark: true,
  colors: {
    ...DefaultTheme.colors,
    primary: colors.accentMint,
    background: colors.bgDeep,
    card: colors.bgSurface,
    text: colors.textPrimary,
    border: colors.glassBorder,
    notification: colors.accentDanger,
  },
};

export default function App() {
  const navigationRef = useRef<NavigationContainerRef<RootTabParamList>>(null);

  useEffect(() => {
    // Initialize language setting
    initLanguage().catch(console.warn);

    // Request notification permissions on first launch
    requestNotificationPermissions().catch(console.warn);

    // Handle notification taps — navigate to the right screen
    const subscription = addNotificationResponseListener((data) => {
      const nav = navigationRef.current;
      if (!nav) return;

      switch (data.type) {
        case 'scan_complete':
        case 'scheduled_scan':
          nav.navigate('Scanner');
          break;
        case 'critical_threat':
          nav.navigate('Remover');
          break;
        case 'daily_digest':
          nav.navigate('Home');
          break;
        case 'remediation_complete':
          nav.navigate('Scanner');
          break;
        default:
          break;
      }
    });

    return () => subscription.remove();
  }, []);

  return (
    <SafeAreaProvider>
      <NavigationContainer ref={navigationRef} theme={ShieldScanTheme}>
        <StatusBar style="light" />
        <AppNavigator />
      </NavigationContainer>
    </SafeAreaProvider>
  );
}
