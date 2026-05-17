/**
 * ShieldScan — AI Analysis Configuration
 *
 * Manages API keys and consent for cloud-assisted threat analysis.
 * Keys stored in AsyncStorage. Consent is explicit opt-in (default OFF).
 *
 * Providers (fallback order):
 *   1. Google Gemini 2.5 Flash (free: 15 RPM, 1,500 req/day, 1M context)
 *   2. Groq — Llama 3.3 70B (free: 30 RPM, 6K TPM, 1K req/day)
 *   3. Zhipu GLM-4.7 Flash (free: 1,000 req/day, 200K context, MIT)
 *   4. OpenRouter — DeepSeek R1 671B (free: 20 RPM, 200 req/day)
 */

import AsyncStorage from '@react-native-async-storage/async-storage';

const KEYS = {
  consent: '@shieldscan_ai_consent',
  geminiKey: '@shieldscan_ai_gemini_key',
  groqKey: '@shieldscan_ai_groq_key',
  glmKey: '@shieldscan_ai_glm_key',
  openrouterKey: '@shieldscan_ai_openrouter_key',
};

export type AIProvider = 'gemini' | 'groq' | 'glm' | 'openrouter';

export interface AIConfig {
  consentGiven: boolean;
  geminiKey: string;
  groqKey: string;
  glmKey: string;
  openrouterKey: string;
}

/**
 * Load full AI configuration from storage.
 */
export async function getAIConfig(): Promise<AIConfig> {
  try {
    const [consent, gemini, groq, glm, openrouter] = await Promise.all([
      AsyncStorage.getItem(KEYS.consent),
      AsyncStorage.getItem(KEYS.geminiKey),
      AsyncStorage.getItem(KEYS.groqKey),
      AsyncStorage.getItem(KEYS.glmKey),
      AsyncStorage.getItem(KEYS.openrouterKey),
    ]);
    return {
      consentGiven: consent === 'true',
      geminiKey: gemini || '',
      groqKey: groq || '',
      glmKey: glm || '',
      openrouterKey: openrouter || '',
    };
  } catch {
    return { consentGiven: false, geminiKey: '', groqKey: '', glmKey: '', openrouterKey: '' };
  }
}

/**
 * Set AI analysis consent.
 */
export async function setAIConsent(enabled: boolean): Promise<void> {
  await AsyncStorage.setItem(KEYS.consent, enabled ? 'true' : 'false');
}

/**
 * Save an API key for a specific provider.
 */
export async function setAIKey(provider: AIProvider, key: string): Promise<void> {
  const storageKey =
    provider === 'gemini' ? KEYS.geminiKey :
    provider === 'groq' ? KEYS.groqKey :
    provider === 'glm' ? KEYS.glmKey : KEYS.openrouterKey;
  await AsyncStorage.setItem(storageKey, key.trim());
}

/**
 * Clear all AI configuration.
 */
export async function clearAIConfig(): Promise<void> {
  await Promise.all(Object.values(KEYS).map((k) => AsyncStorage.removeItem(k)));
}

/**
 * Get list of configured providers (have API key set), in fallback order.
 */
export async function getConfiguredProviders(): Promise<AIProvider[]> {
  const config = await getAIConfig();
  const providers: AIProvider[] = [];
  if (config.geminiKey) providers.push('gemini');
  if (config.groqKey) providers.push('groq');
  if (config.glmKey) providers.push('glm');
  if (config.openrouterKey) providers.push('openrouter');
  return providers;
}

/**
 * Provider display info for the Settings UI.
 */
export const AI_PROVIDERS: {
  id: AIProvider;
  name: string;
  model: string;
  freeQuota: string;
  keyUrl: string;
}[] = [
  {
    id: 'gemini',
    name: 'Google Gemini',
    model: 'gemini-2.5-flash',
    freeQuota: '15 RPM · 1,500 req/day · 1M context',
    keyUrl: 'https://aistudio.google.com/apikey',
  },
  {
    id: 'groq',
    name: 'Groq',
    model: 'llama-3.3-70b-versatile',
    freeQuota: '30 RPM · 6K TPM · 1K req/day',
    keyUrl: 'https://console.groq.com/keys',
  },
  {
    id: 'glm',
    name: 'Zhipu GLM (Z.ai)',
    model: 'glm-4.7-flash',
    freeQuota: '1,000 req/day · 200K context',
    keyUrl: 'https://open.bigmodel.cn',
  },
  {
    id: 'openrouter',
    name: 'OpenRouter (DeepSeek R1)',
    model: 'deepseek/deepseek-r1:free',
    freeQuota: '20 RPM · 200 req/day',
    keyUrl: 'https://openrouter.ai/keys',
  },
];
