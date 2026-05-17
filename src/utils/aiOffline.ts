/**
 * ShieldScan — Offline On-Device AI Analysis
 *
 * Uses llama.rn (llama.cpp binding) to run a small language model
 * entirely on-device for threat classification without internet.
 *
 * Model: DeepSeek-R1-Distill-Qwen-1.5B (Q4_K_M quantization)
 *
 * Resource Requirements (shown to user before opt-in):
 *   - Download: ~1.1 GB (one-time, over Wi-Fi recommended)
 *   - Storage: ~1.1 GB on device
 *   - RAM: ~1.5 GB during inference
 *   - CPU: Heavy usage for 15-60s during analysis
 *   - Battery: Moderate drain during inference
 *
 * This is fully optional and disabled by default.
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import * as FileSystem from 'expo-file-system/legacy';
import type { ScanResult, RiskScore } from '../types/engine';
import type { AIAnalysisResult, AIInsight } from './aiAnalysis';

// ─── Constants ─────────────────────────────────────────────────

const STORAGE_KEYS = {
  enabled: '@shieldscan_offline_ai_enabled',
  modelDownloaded: '@shieldscan_offline_model_ready',
};

const MODEL_INFO = {
  name: 'DeepSeek-R1-Distill-Qwen-1.5B',
  filename: 'deepseek-r1-distill-qwen-1.5b-q4_k_m.gguf',
  url: 'https://huggingface.co/bartowski/DeepSeek-R1-Distill-Qwen-1.5B-GGUF/resolve/main/DeepSeek-R1-Distill-Qwen-1.5B-Q4_K_M.gguf',
  sizeBytes: 1_100_000_000, // ~1.1 GB
  sizeMB: 1100,
  requiredRAM_MB: 1500,
  requiredStorage_MB: 1200,
  quantization: 'Q4_K_M',
  parameters: '1.5B',
};

export const OFFLINE_MODEL_INFO = MODEL_INFO;

/** Resource requirements shown to user before enabling */
export const RESOURCE_REQUIREMENTS = {
  downloadSize: '~1.1 GB',
  storageRequired: '~1.2 GB',
  ramDuringInference: '~1.5 GB',
  cpuUsage: 'High (15-60 seconds per analysis)',
  batteryImpact: 'Moderate drain during analysis',
  recommendedRAM: '6 GB+ total device RAM',
  recommendedConnection: 'Wi-Fi (for initial download)',
  modelName: MODEL_INFO.name,
  quantization: MODEL_INFO.quantization,
  note: 'The model is downloaded once and stored locally. All inference runs 100% offline — no data ever leaves your device.',
};

// ─── Config ────────────────────────────────────────────────────

export interface OfflineAIConfig {
  enabled: boolean;
  modelDownloaded: boolean;
}

export async function getOfflineAIConfig(): Promise<OfflineAIConfig> {
  try {
    const [enabled, downloaded] = await Promise.all([
      AsyncStorage.getItem(STORAGE_KEYS.enabled),
      AsyncStorage.getItem(STORAGE_KEYS.modelDownloaded),
    ]);
    return {
      enabled: enabled === 'true',
      modelDownloaded: downloaded === 'true',
    };
  } catch {
    return { enabled: false, modelDownloaded: false };
  }
}

export async function setOfflineAIEnabled(enabled: boolean): Promise<void> {
  await AsyncStorage.setItem(STORAGE_KEYS.enabled, enabled ? 'true' : 'false');
}

// ─── Model Management ──────────────────────────────────────────

function getModelPath(): string {
  return `${FileSystem.documentDirectory}models/${MODEL_INFO.filename}`;
}

/** Check if model file exists on device */
export async function isModelDownloaded(): Promise<boolean> {
  try {
    const path = getModelPath();
    const info = await FileSystem.getInfoAsync(path);
    if (info.exists && !info.isDirectory && info.size && info.size > MODEL_INFO.sizeBytes * 0.9) {
      await AsyncStorage.setItem(STORAGE_KEYS.modelDownloaded, 'true');
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

/** Download model with progress callback */
export async function downloadModel(
  onProgress?: (progress: number) => void,
): Promise<{ success: boolean; error?: string }> {
  try {
    // Ensure directory exists
    const dir = `${FileSystem.documentDirectory}models`;
    const dirInfo = await FileSystem.getInfoAsync(dir);
    if (!dirInfo.exists) {
      await FileSystem.makeDirectoryAsync(dir, { intermediates: true });
    }

    const path = getModelPath();

    // Download with progress tracking
    const downloadResumable = FileSystem.createDownloadResumable(
      MODEL_INFO.url,
      path,
      {},
      (downloadProgress) => {
        const progress = downloadProgress.totalBytesWritten / downloadProgress.totalBytesExpectedToWrite;
        onProgress?.(Math.round(progress * 100));
      },
    );

    const result = await downloadResumable.downloadAsync();
    if (!result || !result.uri) {
      throw new Error('Download returned empty result');
    }

    // Verify file size
    const info = await FileSystem.getInfoAsync(path);
    if (!info.exists || !info.size || info.size < MODEL_INFO.sizeBytes * 0.9) {
      throw new Error('Downloaded file is incomplete or corrupted');
    }

    await AsyncStorage.setItem(STORAGE_KEYS.modelDownloaded, 'true');
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message || 'Download failed' };
  }
}

/** Delete model to free storage */
export async function deleteModel(): Promise<void> {
  try {
    const path = getModelPath();
    const info = await FileSystem.getInfoAsync(path);
    if (info.exists) {
      await FileSystem.deleteAsync(path);
    }
    await AsyncStorage.setItem(STORAGE_KEYS.modelDownloaded, 'false');
  } catch {}
}

/** Get current storage usage */
export async function getModelStorageUsage(): Promise<number> {
  try {
    const path = getModelPath();
    const info = await FileSystem.getInfoAsync(path);
    if (info.exists && info.size) {
      return info.size;
    }
    return 0;
  } catch {
    return 0;
  }
}

// ─── Inference ─────────────────────────────────────────────────

let llamaContext: any = null;

async function getOrCreateContext() {
  if (llamaContext) return llamaContext;

  const { initLlama } = require('llama.rn');
  const modelPath = getModelPath();

  llamaContext = await initLlama({
    model: modelPath,
    n_ctx: 2048,
    n_batch: 256,
    n_threads: 4,
    use_mlock: false,
    use_mmap: true,
  });

  return llamaContext;
}

/** Release model from memory */
export async function unloadModel(): Promise<void> {
  if (llamaContext) {
    try {
      await llamaContext.release();
    } catch {}
    llamaContext = null;
  }
}

/**
 * Run offline analysis on scan findings.
 * Returns null if offline AI is not enabled or model not downloaded.
 */
export async function analyzeOffline(
  findings: ScanResult[],
  riskScore: RiskScore | null,
): Promise<AIAnalysisResult | null> {
  const config = await getOfflineAIConfig();
  if (!config.enabled || !config.modelDownloaded) {
    return null;
  }

  // Verify model exists
  const exists = await isModelDownloaded();
  if (!exists) {
    return null;
  }

  try {
    const context = await getOrCreateContext();

    // Build a shorter prompt for the small model (1.5B can't handle too much)
    const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, safe: 0 };
    const topFindings = [...findings]
      .sort((a, b) => (sevOrder[b.severity] ?? 0) - (sevOrder[a.severity] ?? 0))
      .slice(0, 5);

    const prompt = buildOfflinePrompt(topFindings, riskScore);

    const result = await context.completion({
      prompt,
      n_predict: 1024,
      temperature: 0.2,
      top_p: 0.9,
      stop: ['</s>', '\n\n\n'],
    });

    const text = result.text || '';
    return parseOfflineResponse(text, findings);
  } catch (err: any) {
    console.warn('[OfflineAI] Inference failed:', err.message);
    return {
      provider: 'gemini', // placeholder — overridden below
      model: `${MODEL_INFO.name} (on-device)`,
      summary: '',
      insights: [],
      overallAssessment: '',
      timestamp: Date.now(),
      error: `On-device analysis failed: ${err.message}`,
    };
  }
}

// ─── Prompt & Parser (optimized for small model) ───────────────

function buildOfflinePrompt(
  findings: ScanResult[],
  riskScore: RiskScore | null,
): string {
  const findingsList = findings.map((f, i) =>
    `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}: ${f.description.slice(0, 100)}`
  ).join('\n');

  return `<|im_start|>system
You are a mobile security analyst. Classify threats and give brief remediation advice. Respond in JSON only.
<|im_end|>
<|im_start|>user
Risk score: ${riskScore?.overall ?? '?'}/100. Top findings:
${findingsList}

Respond as JSON: {"summary":"1 sentence","insights":[{"index":1,"priority":"immediate|high|moderate|low","advice":"1 sentence"}]}
<|im_end|>
<|im_start|>assistant
`;
}

function parseOfflineResponse(
  raw: string,
  findings: ScanResult[],
): AIAnalysisResult {
  try {
    // Try to extract JSON
    let jsonStr = raw.trim();
    const jsonMatch = jsonStr.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      jsonStr = jsonMatch[0];
    }

    const parsed = JSON.parse(jsonStr);

    const insights: AIInsight[] = (parsed.insights || []).map((ins: any) => {
      const idx = (ins.index || 1) - 1;
      const finding = findings[idx];
      return {
        findingId: finding?.id || `offline-${idx}`,
        analysis: ins.advice || ins.analysis || '',
        riskExplanation: '',
        attackVector: '',
        priority: ins.priority || 'moderate',
        remediationSteps: ins.advice ? [ins.advice] : [],
      };
    });

    return {
      provider: 'gemini', // not used — we mark it differently in UI
      model: `${MODEL_INFO.name} (on-device)`,
      summary: parsed.summary || 'Offline analysis complete.',
      insights,
      overallAssessment: '',
      timestamp: Date.now(),
    };
  } catch {
    return {
      provider: 'gemini',
      model: `${MODEL_INFO.name} (on-device)`,
      summary: raw.slice(0, 300) || 'Analysis produced unstructured output.',
      insights: [],
      overallAssessment: '',
      timestamp: Date.now(),
      error: 'On-device model returned non-JSON — showing raw output',
    };
  }
}
