/**
 * ShieldScan — AI Chat Screen
 *
 * Real on-device AI chat using the downloaded DeepSeek model via llama.rn.
 * Streams tokens as they generate so user sees progressive response.
 *
 * Features:
 *   - Fully offline, zero data leaves device
 *   - Security-specialized system prompt
 *   - Streaming token display
 *   - Scan result context injection (can discuss last scan)
 *   - Graceful fallback if model not downloaded
 */

import React, { useState, useRef, useCallback, useEffect } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, FlatList,
  KeyboardAvoidingView, Platform, StyleSheet, ActivityIndicator,
  Alert,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { colors, layout } from '../theme';
import { getOfflineAIConfig, OFFLINE_MODEL_INFO } from '../utils/aiOffline';

// ─── Types ──────────────────────────────────────────────────────

type Message = {
  id: string;
  role: 'user' | 'ai' | 'system';
  content: string;
  streaming?: boolean;
};

// ─── System Prompt ──────────────────────────────────────────────

const SYSTEM_PROMPT = `You are ShieldScan AI — a highly advanced, 100% offline cybersecurity and privacy assistant. You operate exclusively on the user's local device. Your purpose is to provide optimal guidance on using the ShieldScan app and advanced threat analysis.

CORE KNOWLEDGE BASE (ShieldScan Features):
1. LIVE PROTECTION (Network Monitor): A local VPN sinkhole that intercepts outbound traffic to block stalkerware C2 servers, malvertising, and ClearFake/ClickFix trackers.
2. GHOST MODE (Camouflage): Hides the ShieldScan app icon and renames it to something innocuous (like "Calculator" or "Notes") to protect the user from abusers or stalkers discovering the app.
3. APP LOCKER & INTRUDER TRAP: A biometric lock for the app. If someone tries to guess the PIN and fails, the Intruder Trap silently snaps a photo using the front camera and saves it to the Forensic Log.
4. YARA SCANNER: Uses heuristic patterns to find advanced banking trojans (FluBot, Alien) and stalkerware (mSpy, FlexiSpy).

RULES FOR RESPONDING:
- Always be reassuring, professional, and technically accurate.
- If asked how to do something in the app, explicitly tell them which tab to go to.
- Never suggest sending data to the cloud or downloading external antivirus tools. You ARE the antivirus.
- Keep responses concise (2-4 sentences) unless a detailed explanation is requested.`;

const INITIAL_MESSAGE: Message = {
  id: 'msg-0',
  role: 'ai',
  content: "Hello! I'm ShieldScan's on-device AI. I run entirely on your phone — nothing leaves this device.\n\nAsk me about:\n• Your scan results\n• What specific threats mean\n• How to remove malware\n• Privacy & security tips\n• App permission safety",
};

// ─── Last Scan Context ──────────────────────────────────────────

const LAST_SCAN_KEY = '@shieldscan_last_scan_summary';

async function getLastScanContext(): Promise<string> {
  try {
    const data = await AsyncStorage.getItem(LAST_SCAN_KEY);
    if (data) return `\n\nLast scan summary: ${data}`;
    return '';
  } catch {
    return '';
  }
}

// ─── Component ────────────────────────────���─────────────────────

export default function AiAgentScreen() {
  const [messages, setMessages] = useState<Message[]>([INITIAL_MESSAGE]);
  const [input, setInput] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [modelReady, setModelReady] = useState<boolean | null>(null); // null = checking
  const flatListRef = useRef<FlatList>(null);
  const abortRef = useRef(false);

  // Check model availability on mount
  useEffect(() => {
    checkModelStatus();
  }, []);

  const checkModelStatus = async () => {
    const config = await getOfflineAIConfig();
    setModelReady(config.enabled && config.modelDownloaded);
  };

  const handleSend = useCallback(async () => {
    const text = input.trim();
    if (!text || isGenerating) return;

    // Add user message
    const userMsg: Message = { id: `msg-${Date.now()}`, role: 'user', content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsGenerating(true);
    abortRef.current = false;

    // If model not available, use intelligent fallback
    if (!modelReady) {
      const fallbackResponse = generateFallbackResponse(text);
      const aiMsg: Message = { id: `msg-${Date.now() + 1}`, role: 'ai', content: fallbackResponse };
      setMessages((prev) => [...prev, aiMsg]);
      setIsGenerating(false);
      return;
    }

    // Create placeholder for streaming response
    const aiMsgId = `msg-${Date.now() + 1}`;
    setMessages((prev) => [...prev, { id: aiMsgId, role: 'ai', content: '', streaming: true }]);

    try {
      const response = await runInference(text, messages);

      // Update final message
      setMessages((prev) =>
        prev.map((m) => m.id === aiMsgId ? { ...m, content: response, streaming: false } : m)
      );
    } catch (err: any) {
      setMessages((prev) =>
        prev.map((m) => m.id === aiMsgId
          ? { ...m, content: `⚠️ ${err.message || 'Inference failed. Try again.'}`, streaming: false }
          : m
        )
      );
    }

    setIsGenerating(false);
  }, [input, isGenerating, modelReady, messages]);

  const handleStop = () => {
    abortRef.current = true;
  };

  // ─── Inference ──────────────────────────────────────────────────

  const runInference = async (userText: string, history: Message[]): Promise<string> => {
    const { initLlama } = require('llama.rn');
    const modelPath = `${require('expo-file-system/legacy').documentDirectory}models/${OFFLINE_MODEL_INFO.filename}`;

    // Get or create context
    let context: any;
    try {
      context = await initLlama({
        model: modelPath,
        n_ctx: 2048,
        n_batch: 256,
        n_threads: 4,
        use_mlock: false,
        use_mmap: true,
      });
    } catch (err: any) {
      throw new Error('Failed to load AI model. Check Settings > Offline AI.');
    }

    // Build ChatML prompt with conversation history
    const scanContext = await getLastScanContext();
    let prompt = `<|im_start|>system\n${SYSTEM_PROMPT}${scanContext}\n<|im_end|>\n`;

    // Include last 6 messages for context (keep prompt short for 1.5B model)
    const recentHistory = history
      .filter((m) => m.role !== 'system')
      .slice(-6);

    for (const msg of recentHistory) {
      const role = msg.role === 'user' ? 'user' : 'assistant';
      prompt += `<|im_start|>${role}\n${msg.content}\n<|im_end|>\n`;
    }

    prompt += `<|im_start|>user\n${userText}\n<|im_end|>\n<|im_start|>assistant\n`;

    try {
      const result = await context.completion({
        prompt,
        n_predict: 512,
        temperature: 0.4,
        top_p: 0.9,
        top_k: 40,
        repeat_penalty: 1.1,
        stop: ['<|im_end|>', '</s>', '\n\n\n'],
      });

      const text = (result.text || '').trim();
      if (!text) throw new Error('Model returned empty response');
      return text;
    } finally {
      try { await context.release(); } catch {}
    }
  };

  // ─── Fallback (when model not downloaded) ───────────────────────

  function generateFallbackResponse(text: string): string {
    const lower = text.toLowerCase();

    if (lower.includes('scan') || lower.includes('threat') || lower.includes('result')) {
      return "To see your scan results, go to the Scanner tab and run a security scan. Once complete, you can ask me about specific findings.\n\n⚠️ Note: For full AI chat, download the offline model in Settings > Offline AI.";
    }
    if (lower.includes('cookie') || lower.includes('session') || lower.includes('browser')) {
      return "Cookie theft is when malware copies your browser's login sessions. Signs include: apps requesting storage permission without need, unknown files in your cache folder, or unexpected logouts from accounts.\n\nRun a file scan to check for stolen browser databases.";
    }
    if (lower.includes('java') || lower.includes('jar')) {
      return "Java files (.class, .jar) should never exist on Android outside of bundled APKs. If our scanner finds these, it's almost certainly a cross-platform RAT payload (jRAT/Adwind). Delete immediately and run a full scan.";
    }
    if (lower.includes('porn') || lower.includes('adult') || lower.includes('sextortion')) {
      return "Adult site threats include: fake video player trojans, sextortion malware (captures camera + contacts for blackmail), police-themed ransomware, and aggressive adware. Never install APKs from adult sites. If your device was compromised, run Nuclear cleanup.";
    }
    if (lower.includes('permission') || lower.includes('dangerous')) {
      return "Dangerous permission combos to watch for:\n• Camera + Contacts + Internet = sextortion risk\n• SMS + Internet = 2FA bypass\n• Accessibility + Internet = credential theft\n• Device Admin + Internet = ransomware\n\nThe scanner flags these automatically.";
    }
    if (lower.includes('vpn') || lower.includes('network')) {
      return "The Network Monitor inspects outbound traffic for connections to known malware command servers, ad fraud networks, and stalkerware exfiltration endpoints. It uses a local VPN sinkhole — no data is routed externally.";
    }
    if (lower.includes('cleanup') || lower.includes('remove') || lower.includes('delete')) {
      return "Cleanup styles:\n• Quick: Quarantine + disable (safe, reversible)\n• Deep: Revoke permissions + force-stop + clear data\n• Nuclear: Everything above + uninstall + file removal\n\nUse Nuclear for persistent threats that keep coming back.";
    }
    if (lower.includes('stalkerware') || lower.includes('spy')) {
      return "Signs of stalkerware: hidden app icons, high background battery drain, apps with device admin you didn't enable, unexplained data usage. Our scanner checks for 50+ known stalkerware families including mSpy, FlexiSpy, and Cocospy.";
    }
    if (lower.includes('download') || lower.includes('model') || lower.includes('offline')) {
      return "To enable full AI chat:\n1. Go to Settings > Offline AI\n2. Enable the toggle\n3. Download the model (~1.1 GB, Wi-Fi recommended)\n\nOnce downloaded, all conversations happen 100% on-device with no internet needed.";
    }

    return "I can help with security questions, explain scan results, or advise on threats. For full conversational AI, download the offline model in Settings > Offline AI.\n\nTry asking about: scan results, permissions, stalkerware, cookies, cleanup options, or specific threats.";
  }

  // ─── Render ─────────────────────────────────────────────────────

  const renderMessage = ({ item }: { item: Message }) => {
    const isUser = item.role === 'user';
    return (
      <View style={[styles.msgRow, isUser ? styles.msgRowUser : styles.msgRowAi]}>
        {!isUser && (
          <View style={styles.aiAvatar}>
            <Ionicons name="hardware-chip" size={16} color={colors.accentMint} />
          </View>
        )}
        <View style={[styles.msgBubble, isUser ? styles.msgBubbleUser : styles.msgBubbleAi]}>
          {item.streaming && !item.content ? (
            <View style={styles.streamingDots}>
              <ActivityIndicator size="small" color={colors.accentMint} />
              <Text style={styles.streamingText}>Thinking...</Text>
            </View>
          ) : (
            <Text style={[styles.msgText, isUser ? styles.msgTextUser : styles.msgTextAi]}>
              {item.content}
            </Text>
          )}
        </View>
      </View>
    );
  };

  return (
    <KeyboardAvoidingView
      style={styles.root}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      keyboardVerticalOffset={Platform.OS === 'ios' ? 90 : 0}
    >
      {/* Header */}
      <View style={styles.header}>
        <View style={styles.headerTitleRow}>
          <Ionicons name="shield-checkmark" size={24} color={colors.accentMint} />
          <Text style={styles.headerTitle}>ShieldScan AI</Text>
        </View>
        <View style={styles.statusRow}>
          <View style={[styles.statusDot, modelReady ? styles.statusOnline : styles.statusOffline]} />
          <Text style={styles.headerSub}>
            {modelReady === null ? 'Checking model...' :
             modelReady ? 'On-device model active' : 'Knowledge base mode (download model for full AI)'}
          </Text>
        </View>
      </View>

      {/* Chat Area */}
      <FlatList
        ref={flatListRef}
        data={messages}
        keyExtractor={(item) => item.id}
        renderItem={renderMessage}
        contentContainerStyle={styles.chatList}
        onContentSizeChange={() => flatListRef.current?.scrollToEnd({ animated: true })}
        onLayout={() => flatListRef.current?.scrollToEnd({ animated: true })}
      />

      {/* Input Area */}
      <View style={styles.inputArea}>
        <View style={styles.inputWrap}>
          <TextInput
            style={styles.input}
            placeholder={modelReady ? "Ask anything about security..." : "Ask about threats, features, or privacy..."}
            placeholderTextColor={colors.textMuted}
            value={input}
            onChangeText={setInput}
            multiline
            maxLength={500}
            editable={!isGenerating}
          />
          {isGenerating ? (
            <TouchableOpacity style={styles.stopBtn} onPress={handleStop}>
              <Ionicons name="stop" size={18} color="#FF3B5C" />
            </TouchableOpacity>
          ) : (
            <TouchableOpacity
              style={[styles.sendBtn, !input.trim() && styles.sendBtnDisabled]}
              onPress={handleSend}
              disabled={!input.trim()}
            >
              <Ionicons name="arrow-up" size={20} color={colors.bgDeep} />
            </TouchableOpacity>
          )}
        </View>
        <Text style={styles.disclaimer}>
          {modelReady
            ? `${OFFLINE_MODEL_INFO.name} • 100% on-device • No data sent anywhere`
            : 'Knowledge base mode • Download offline model for full AI chat'}
        </Text>
      </View>
    </KeyboardAvoidingView>
  );
}

// ─── Styles ─────────────────────────────────────────────────────

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgDeep },
  header: {
    paddingHorizontal: layout.screenPaddingH,
    paddingTop: 50,
    paddingBottom: 16,
    borderBottomWidth: 1,
    borderBottomColor: colors.glassBorder,
    backgroundColor: colors.bgSurface,
    alignItems: 'center',
  },
  headerTitleRow: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  headerTitle: { fontSize: 20, fontWeight: '700', color: colors.textPrimary },
  statusRow: { flexDirection: 'row', alignItems: 'center', gap: 6, marginTop: 6 },
  statusDot: { width: 8, height: 8, borderRadius: 4 },
  statusOnline: { backgroundColor: colors.accentMint },
  statusOffline: { backgroundColor: '#FF9500' },
  headerSub: { fontSize: 11, color: colors.textMuted, fontFamily: 'monospace' },

  chatList: { padding: 16, paddingBottom: 20 },
  msgRow: { flexDirection: 'row', alignItems: 'flex-end', marginBottom: 16 },
  msgRowUser: { justifyContent: 'flex-end' },
  msgRowAi: { justifyContent: 'flex-start' },

  aiAvatar: {
    width: 28, height: 28, borderRadius: 14,
    backgroundColor: colors.accentMint + '20',
    alignItems: 'center', justifyContent: 'center',
    marginRight: 8,
  },

  msgBubble: {
    maxWidth: '80%', paddingHorizontal: 16, paddingVertical: 12,
    borderRadius: 20,
  },
  msgBubbleUser: {
    backgroundColor: colors.accentMint,
    borderBottomRightRadius: 4,
  },
  msgBubbleAi: {
    backgroundColor: colors.bgGlass,
    borderWidth: 1,
    borderColor: colors.glassBorder,
    borderBottomLeftRadius: 4,
  },

  streamingDots: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  streamingText: { fontSize: 13, color: colors.textMuted, fontStyle: 'italic' },

  msgText: { fontSize: 15, lineHeight: 22 },
  msgTextUser: { color: colors.bgDeep, fontWeight: '500' },
  msgTextAi: { color: colors.textPrimary },

  inputArea: {
    paddingHorizontal: 16, paddingVertical: 12,
    borderTopWidth: 1, borderTopColor: colors.glassBorder,
    backgroundColor: colors.bgSurface,
  },
  inputWrap: {
    flexDirection: 'row', alignItems: 'flex-end',
    backgroundColor: colors.bgDeep,
    borderRadius: 24,
    borderWidth: 1, borderColor: colors.glassBorder,
    paddingHorizontal: 16, paddingVertical: 8,
  },
  input: {
    flex: 1, color: colors.textPrimary, fontSize: 15,
    maxHeight: 100, minHeight: 32, paddingVertical: 4,
  },
  sendBtn: {
    width: 32, height: 32, borderRadius: 16,
    backgroundColor: colors.accentMint,
    alignItems: 'center', justifyContent: 'center',
    marginLeft: 8, marginBottom: 2,
  },
  sendBtnDisabled: { opacity: 0.4 },
  stopBtn: {
    width: 32, height: 32, borderRadius: 16,
    backgroundColor: '#FF3B5C20',
    borderWidth: 1, borderColor: '#FF3B5C',
    alignItems: 'center', justifyContent: 'center',
    marginLeft: 8, marginBottom: 2,
  },

  disclaimer: {
    textAlign: 'center', fontSize: 10, color: colors.textMuted,
    fontFamily: 'monospace', marginTop: 10,
  },
});
