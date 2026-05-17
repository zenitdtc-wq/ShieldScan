/**
 * ShieldScan i18n — Translation system
 *
 * Supports English and Dutch. Language preference persisted in AsyncStorage.
 * Usage: import { t, setLanguage, getLanguage } from '../i18n';
 *        t('scanner.title')  // => "Run Full Security Scan"
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import en from './en';
import nl from './nl';

const STORAGE_KEY = '@shieldscan_language';

export type SupportedLanguage = 'en' | 'nl';

const translations: Record<SupportedLanguage, Record<string, Record<string, string>>> = {
  en,
  nl,
};

let currentLanguage: SupportedLanguage = 'en';
let listeners: Array<(lang: SupportedLanguage) => void> = [];

/**
 * Initialize the i18n system — loads persisted language preference.
 * Call once at app startup.
 */
export async function initLanguage(): Promise<SupportedLanguage> {
  try {
    const stored = await AsyncStorage.getItem(STORAGE_KEY);
    if (stored === 'en' || stored === 'nl') {
      currentLanguage = stored;
    }
  } catch {
    // Default to English
  }
  return currentLanguage;
}

/**
 * Get translation for a dot-separated key.
 * Example: t('scanner.title') => "Run Full Security Scan"
 */
export function t(key: string): string {
  const [section, field] = key.split('.');
  if (!section || !field) return key;

  const dict = translations[currentLanguage];
  return dict?.[section]?.[field] ?? translations.en?.[section]?.[field] ?? key;
}

/**
 * Get current language code.
 */
export function getLanguage(): SupportedLanguage {
  return currentLanguage;
}

/**
 * Set language and persist to AsyncStorage.
 * Notifies all registered listeners.
 */
export async function setLanguage(lang: SupportedLanguage): Promise<void> {
  if (lang !== 'en' && lang !== 'nl') return;
  currentLanguage = lang;
  try {
    await AsyncStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // Persist failed, but in-memory value is updated
  }
  listeners.forEach((cb) => cb(lang));
}

/**
 * Subscribe to language changes. Returns unsubscribe function.
 */
export function onLanguageChange(cb: (lang: SupportedLanguage) => void): () => void {
  listeners.push(cb);
  return () => {
    listeners = listeners.filter((l) => l !== cb);
  };
}

/**
 * Available languages with display names.
 */
export const AVAILABLE_LANGUAGES: { code: SupportedLanguage; label: string; flag: string }[] = [
  { code: 'en', label: 'English', flag: '🇬🇧' },
  { code: 'nl', label: 'Nederlands', flag: '🇳🇱' },
];
