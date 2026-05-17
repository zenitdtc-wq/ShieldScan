/**
 * Navigation type definitions
 */

export type RootTabParamList = {
  Home: undefined;
  Scanner: undefined;
  Remover: undefined;
  Intel: undefined;
  Tools: undefined;
  Settings: undefined;
  LiveProtection: undefined;
  ForensicLog: undefined;
};

export type RootStackParamList = {
  MainTabs: undefined;
  ScanDetail: { scanId: string };
  ThreatDetail: { threatId: string };
  GhostModeSettings: undefined;
  LockerScreen: undefined;
  NetworkMonitorScreen: undefined;
  AiAgentScreen: undefined;
};
