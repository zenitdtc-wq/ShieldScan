import React from 'react';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { colors } from '../theme';
import type { RootTabParamList, RootStackParamList } from '../types/navigation';

import HomeScreen from '../screens/HomeScreen';
import ScannerScreen from '../screens/ScannerScreen';
import RemoverScreen from '../screens/RemoverScreen';
import IntelScreen from '../screens/IntelScreen';
import ToolsScreen from '../screens/ToolsScreen';
import SettingsScreen from '../screens/SettingsScreen';
import LiveProtectionScreen from '../screens/LiveProtectionScreen';
import ForensicLogScreen from '../screens/ForensicLogScreen';
import GhostModeSettings from '../screens/GhostModeSettings';
import LockerScreen from '../screens/LockerScreen';
import NetworkMonitorScreen from '../screens/NetworkMonitorScreen';
import AiAgentScreen from '../screens/AiAgentScreen';
import ScrollableTabBar from '../components/common/ScrollableTabBar';

const Tab = createBottomTabNavigator<RootTabParamList>();
const Stack = createNativeStackNavigator<RootStackParamList>();

function TabNavigator() {
  return (
    <Tab.Navigator
      tabBar={(props) => <ScrollableTabBar {...props} />}
      screenOptions={{ headerShown: false }}
    >
      <Tab.Screen name="Home" component={HomeScreen} />
      <Tab.Screen name="Scanner" component={ScannerScreen} />
      <Tab.Screen name="Remover" component={RemoverScreen} />
      <Tab.Screen name="Intel" component={IntelScreen} />
      <Tab.Screen name="Tools" component={ToolsScreen} />
      <Tab.Screen name="LiveProtection" component={LiveProtectionScreen} options={{ title: 'Live' }} />
      <Tab.Screen name="ForensicLog" component={ForensicLogScreen} options={{ title: 'Log' }} />
      <Tab.Screen name="Settings" component={SettingsScreen} />
    </Tab.Navigator>
  );
}

export default function AppNavigator() {
  return (
    <Stack.Navigator screenOptions={{ headerShown: false }}>
      <Stack.Screen name="MainTabs" component={TabNavigator} />
      <Stack.Screen name="GhostModeSettings" component={GhostModeSettings} />
      <Stack.Screen name="LockerScreen" component={LockerScreen} />
      <Stack.Screen name="NetworkMonitorScreen" component={NetworkMonitorScreen} />
      <Stack.Screen name="AiAgentScreen" component={AiAgentScreen} />
    </Stack.Navigator>
  );
}
