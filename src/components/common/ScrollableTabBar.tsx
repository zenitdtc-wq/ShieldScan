/**
 * ShieldScan — Scrollable Tab Bar
 *
 * Custom bottom tab bar that supports 8 tabs on small screens (Samsung A53 etc.)
 * by allowing horizontal scrolling. Replaces the default React Navigation tab bar.
 */

import React, { useRef, useEffect } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  ScrollView,
  StyleSheet,
  Dimensions,
  Platform,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import type { BottomTabBarProps } from '@react-navigation/bottom-tabs';
import { colors, borderRadius } from '../../theme';

const TAB_ICONS: Record<string, { focused: keyof typeof Ionicons.glyphMap; default: keyof typeof Ionicons.glyphMap }> = {
  Home: { focused: 'home', default: 'home-outline' },
  Scanner: { focused: 'scan', default: 'scan-outline' },
  Remover: { focused: 'trash', default: 'trash-outline' },
  Intel: { focused: 'book', default: 'book-outline' },
  Tools: { focused: 'construct', default: 'construct-outline' },
  Settings: { focused: 'settings', default: 'settings-outline' },
  LiveProtection: { focused: 'shield-checkmark', default: 'shield-checkmark-outline' },
  ForensicLog: { focused: 'document-text', default: 'document-text-outline' },
};

const TAB_MIN_WIDTH = 68;
const { width: SCREEN_WIDTH } = Dimensions.get('window');

export default function ScrollableTabBar({
  state,
  descriptors,
  navigation,
}: BottomTabBarProps) {
  const scrollRef = useRef<ScrollView>(null);
  const insets = useSafeAreaInsets();
  const tabCount = state.routes.length;

  // Calculate if tabs fit without scrolling
  const tabWidth = Math.max(TAB_MIN_WIDTH, Math.floor(SCREEN_WIDTH / tabCount));
  const totalWidth = tabWidth * tabCount;
  const needsScroll = totalWidth > SCREEN_WIDTH;

  // Auto-scroll to active tab
  useEffect(() => {
    if (needsScroll && scrollRef.current) {
      const targetX = Math.max(
        0,
        state.index * tabWidth - SCREEN_WIDTH / 2 + tabWidth / 2,
      );
      scrollRef.current.scrollTo({ x: targetX, animated: true });
    }
  }, [state.index, needsScroll, tabWidth]);

  const renderTab = (route: (typeof state.routes)[0], index: number) => {
    const { options } = descriptors[route.key];
    const label =
      typeof options.tabBarLabel === 'string'
        ? options.tabBarLabel
        : options.title !== undefined
        ? options.title
        : route.name;

    const isFocused = state.index === index;
    const icons = TAB_ICONS[route.name] || { focused: 'help-circle', default: 'help-circle-outline' };
    const iconName = isFocused ? icons.focused : icons.default;
    const tintColor = isFocused ? colors.accentMint : colors.textMuted;

    const onPress = () => {
      const event = navigation.emit({
        type: 'tabPress',
        target: route.key,
        canPreventDefault: true,
      });

      if (!isFocused && !event.defaultPrevented) {
        navigation.navigate(route.name);
      }
    };

    const onLongPress = () => {
      navigation.emit({
        type: 'tabLongPress',
        target: route.key,
      });
    };

    return (
      <TouchableOpacity
        key={route.key}
        accessibilityRole="button"
        accessibilityState={isFocused ? { selected: true } : {}}
        accessibilityLabel={options.tabBarAccessibilityLabel}
        onPress={onPress}
        onLongPress={onLongPress}
        style={[
          styles.tab,
          { width: needsScroll ? TAB_MIN_WIDTH : tabWidth },
          isFocused && styles.tabFocused,
        ]}
        activeOpacity={0.7}
      >
        <Ionicons name={iconName} size={22} color={tintColor} />
        <Text
          style={[styles.tabLabel, { color: tintColor }]}
          numberOfLines={1}
          ellipsizeMode="tail"
        >
          {label}
        </Text>
        {isFocused && <View style={styles.activeIndicator} />}
      </TouchableOpacity>
    );
  };

  const content = state.routes.map((route, index) => renderTab(route, index));

  return (
    <View
      style={[
        styles.container,
        { paddingBottom: Math.max(insets.bottom, 8) },
      ]}
    >
      {needsScroll ? (
        <ScrollView
          ref={scrollRef}
          horizontal
          showsHorizontalScrollIndicator={false}
          contentContainerStyle={styles.scrollContent}
          bounces={false}
        >
          {content}
        </ScrollView>
      ) : (
        <View style={styles.staticContent}>{content}</View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    backgroundColor: colors.bgSurface,
    borderTopWidth: 1,
    borderTopColor: colors.glassBorder,
  },
  scrollContent: {
    flexDirection: 'row',
    paddingHorizontal: 4,
  },
  staticContent: {
    flexDirection: 'row',
  },
  tab: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingTop: 8,
    paddingBottom: 4,
    gap: 3,
    position: 'relative',
  },
  tabFocused: {
    // Subtle background glow for active tab
  },
  tabLabel: {
    fontSize: 10,
    fontWeight: '600',
    letterSpacing: 0.2,
  },
  activeIndicator: {
    position: 'absolute',
    top: 0,
    width: 24,
    height: 2,
    borderRadius: 1,
    backgroundColor: colors.accentMint,
  },
});
