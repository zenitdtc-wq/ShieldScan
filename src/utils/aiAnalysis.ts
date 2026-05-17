/**
 * ShieldScan — AI-Assisted Threat Analysis
 *
 * Sends anonymized scan findings to free AI models for enhanced analysis.
 * Fallback chain: Gemini 2.5 Flash → Groq Llama 3.3 70B → OpenRouter DeepSeek R1
 *
 * Privacy: Only permission names, severity levels, module IDs, and
 * generic descriptions are sent. No device IDs, user data, or
 * identifying information leaves the device.
 */

import type { ScanResult, RiskScore } from '../types/engine';
import { getAIConfig, getConfiguredProviders, AI_PROVIDERS, type AIProvider } from './aiConfig';

// ─── Types ──────────────────────────────────────────────────────

export interface AIInsight {
  findingId: string;
  analysis: string;
  riskExplanation: string;
  attackVector: string;
  priority: 'immediate' | 'high' | 'moderate' | 'low';
  remediationSteps: string[];
}

export interface AIAnalysisResult {
  provider: AIProvider;
  model: string;
  summary: string;
  insights: AIInsight[];
  overallAssessment: string;
  timestamp: number;
  error?: string;
}

// ─── Prompt Builder ─────────────────────────────────────────────

function buildAnalysisPrompt(
  findings: ScanResult[],
  riskScore: RiskScore | null,
): string {
  // Anonymize: strip package names to first segment, remove any PII
  const anonymized = findings.map((f, i) => ({
    index: i + 1,
    module: f.moduleId,
    severity: f.severity,
    title: f.title,
    description: f.description
      .replace(/[a-z]+\.[a-z]+\.[a-z]+[.\w]*/gi, '[package]'), // Strip full package names
    evidence: (f.evidence || [])
      .map((e) => e.replace(/[a-z]+\.[a-z]+\.[a-z]+[.\w]*/gi, '[package]'))
      .slice(0, 4),
    confidence: f.confidence,
    correlated: f.correlated || false,
  }));

  const prompt = `You are a mobile security analyst. Analyze these Android device scan findings and provide actionable threat intelligence.

SCAN SUMMARY:
- Total findings: ${findings.length}
- Risk score: ${riskScore?.overall ?? 'N/A'}/100 (${riskScore?.level ?? 'unknown'})
- Critical: ${findings.filter((f) => f.severity === 'critical').length}
- High: ${findings.filter((f) => f.severity === 'high').length}
- Medium: ${findings.filter((f) => f.severity === 'medium').length}
- Low: ${findings.filter((f) => f.severity === 'low').length}

FINDINGS:
${anonymized.map((f) => `[${f.index}] [${f.severity.toUpperCase()}] [${f.module}] ${f.title}
  ${f.description}
  Evidence: ${f.evidence.join(', ')}
  ${f.correlated ? 'CORRELATED: Multiple agents flagged this' : ''}
  Confidence: ${f.confidence ?? 'N/A'}%`).join('\n\n')}

Respond in this exact JSON format:
{
  "summary": "2-3 sentence overall threat assessment",
  "overallAssessment": "paragraph explaining the device's security posture and what the user should prioritize",
  "insights": [
    {
      "findingIndex": 1,
      "analysis": "what this finding means in plain language",
      "riskExplanation": "why this is dangerous specifically",
      "attackVector": "how an attacker could exploit this",
      "priority": "immediate|high|moderate|low",
      "remediationSteps": ["step 1", "step 2"]
    }
  ]
}

Focus on the top 10 most critical findings. Be specific, not generic. No Barnum statements.`;

  return prompt;
}

// ─── Provider API Calls ─────────────────────────────────────────

async function callGemini(prompt: string, apiKey: string): Promise<string> {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.3,
        maxOutputTokens: 4096,
        responseMimeType: 'application/json',
      },
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Gemini API error ${response.status}: ${err}`);
  }

  const data = await response.json();
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) throw new Error('Gemini returned empty response');
  return text;
}

async function callGroq(prompt: string, apiKey: string): Promise<string> {
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: 'You are a mobile security analyst. Respond only in valid JSON.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 4096,
      response_format: { type: 'json_object' },
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Groq API error ${response.status}: ${err}`);
  }

  const data = await response.json();
  const text = data?.choices?.[0]?.message?.content;
  if (!text) throw new Error('Groq returned empty response');
  return text;
}

async function callGlm(prompt: string, apiKey: string): Promise<string> {
  const response = await fetch('https://open.bigmodel.cn/api/paas/v4/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: 'glm-4-flash',
      messages: [
        { role: 'system', content: 'You are a mobile security analyst. Respond only in valid JSON.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 4096,
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`GLM API error ${response.status}: ${err}`);
  }

  const data = await response.json();
  const text = data?.choices?.[0]?.message?.content;
  if (!text) throw new Error('GLM returned empty response');
  return text;
}

async function callOpenRouter(prompt: string, apiKey: string): Promise<string> {
  const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
      'HTTP-Referer': 'https://shieldscan.app',
      'X-Title': 'ShieldScan',
    },
    body: JSON.stringify({
      model: 'deepseek/deepseek-r1:free',
      messages: [
        { role: 'system', content: 'You are a mobile security analyst. Respond only in valid JSON.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 4096,
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`OpenRouter API error ${response.status}: ${err}`);
  }

  const data = await response.json();
  const text = data?.choices?.[0]?.message?.content;
  if (!text) throw new Error('OpenRouter returned empty response');
  return text;
}

// ─── Response Parser ────────────────────────────────────────────

function parseAIResponse(
  raw: string,
  provider: AIProvider,
  findings: ScanResult[],
): AIAnalysisResult {
  const providerInfo = AI_PROVIDERS.find((p) => p.id === provider)!;

  try {
    // Extract JSON from response (handle markdown code blocks)
    let jsonStr = raw.trim();
    if (jsonStr.startsWith('```')) {
      jsonStr = jsonStr.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '');
    }

    const parsed = JSON.parse(jsonStr);

    const insights: AIInsight[] = (parsed.insights || []).map((ins: any) => {
      const findingIndex = (ins.findingIndex || 1) - 1;
      const finding = findings[findingIndex];
      return {
        findingId: finding?.id || `unknown-${findingIndex}`,
        analysis: ins.analysis || '',
        riskExplanation: ins.riskExplanation || '',
        attackVector: ins.attackVector || '',
        priority: ins.priority || 'moderate',
        remediationSteps: ins.remediationSteps || [],
      };
    });

    return {
      provider,
      model: providerInfo.model,
      summary: parsed.summary || 'Analysis complete.',
      insights,
      overallAssessment: parsed.overallAssessment || '',
      timestamp: Date.now(),
    };
  } catch (parseErr) {
    // If JSON parsing fails, return the raw text as summary
    return {
      provider,
      model: providerInfo.model,
      summary: raw.slice(0, 500),
      insights: [],
      overallAssessment: raw.slice(0, 1000),
      timestamp: Date.now(),
      error: 'Response parsing failed — showing raw analysis',
    };
  }
}

// ─── Main Analysis Function ─────────────────────────────────────

/**
 * Run AI-assisted analysis on scan findings.
 * Requires user consent and at least one configured API key.
 * Tries providers in fallback order: Gemini → Groq → OpenRouter.
 *
 * Returns null if consent not given or no providers configured.
 */
export async function analyzeFindings(
  findings: ScanResult[],
  riskScore: RiskScore | null,
): Promise<AIAnalysisResult | null> {
  const config = await getAIConfig();

  // Check consent
  if (!config.consentGiven) {
    return null;
  }

  // Get available providers
  const providers = await getConfiguredProviders();
  if (providers.length === 0) {
    return {
      provider: 'gemini',
      model: 'none',
      summary: '',
      insights: [],
      overallAssessment: '',
      timestamp: Date.now(),
      error: 'No API keys configured. Add at least one key in Settings → AI Analysis.',
    };
  }

  // Build prompt
  const prompt = buildAnalysisPrompt(findings, riskScore);

  // Try each provider in fallback order
  const callMap: Record<AIProvider, (prompt: string, key: string) => Promise<string>> = {
    gemini: callGemini,
    groq: callGroq,
    glm: callGlm,
    openrouter: callOpenRouter,
  };

  const keyMap: Record<AIProvider, string> = {
    gemini: config.geminiKey,
    groq: config.groqKey,
    glm: config.glmKey,
    openrouter: config.openrouterKey,
  };

  for (const provider of providers) {
    const key = keyMap[provider];
    if (!key) continue;

    try {
      console.log(`[AI] Trying ${provider}...`);
      const raw = await callMap[provider](prompt, key);
      const result = parseAIResponse(raw, provider, findings);
      console.log(`[AI] ${provider} succeeded — ${result.insights.length} insights`);
      return result;
    } catch (err: any) {
      console.warn(`[AI] ${provider} failed:`, err.message);
      // Continue to next provider
    }
  }

  // All providers failed
  return {
    provider: providers[0],
    model: 'none',
    summary: '',
    insights: [],
    overallAssessment: '',
    timestamp: Date.now(),
    error: 'All AI providers failed. Check API keys and internet connection.',
  };
}

/**
 * Test connectivity to a specific provider.
 */
export async function testProvider(
  provider: AIProvider,
  apiKey: string,
): Promise<{ success: boolean; message: string; latencyMs: number }> {
  const testPrompt = 'Respond with exactly: {"status":"ok","model":"your-model-name"}';
  const callMap: Record<AIProvider, (prompt: string, key: string) => Promise<string>> = {
    gemini: callGemini,
    groq: callGroq,
    glm: callGlm,
    openrouter: callOpenRouter,
  };

  const start = Date.now();
  try {
    const result = await callMap[provider](testPrompt, apiKey);
    const latency = Date.now() - start;
    return {
      success: true,
      message: `Connected in ${latency}ms`,
      latencyMs: latency,
    };
  } catch (err: any) {
    return {
      success: false,
      message: err.message || 'Connection failed',
      latencyMs: Date.now() - start,
    };
  }
}
