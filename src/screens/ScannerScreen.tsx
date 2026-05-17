import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  ActivityIndicator,
  TouchableOpacity,
  Alert,
  Animated,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../types/navigation';
import { colors, spacing, borderRadius } from '../theme';
import { useScanEngine } from '../hooks/useScanEngine';
import GlassCard from '../components/common/GlassCard';
import SeverityBadge from '../components/common/SeverityBadge';
import ProgressRing from '../components/common/ProgressRing';
import ScanButton from '../components/common/ScanButton';
import type { ScanModule, ScanResult, SeverityLevel } from '../types/engine';
import { shareReport, saveReportToFile } from '../utils/reportExport';
import { getScanHistory, type ScanHistoryEntry } from '../utils/scheduler';
import { estimateIPGeo } from '../utils/threatTrace';
import { analyzeFindings as aiAnalyzeFindings, type AIAnalysisResult } from '../utils/aiAnalysis';
import { getAIConfig } from '../utils/aiConfig';
import { analyzeOffline, getOfflineAIConfig } from '../utils/aiOffline';
import { executeCleanup, detectRecurrence, CLEANUP_STYLES, type CleanupStyle, type CleanupProgress } from '../utils/cleanupEngine';
import { scanFiles, type FileScanProgress } from '../utils/fileScanner';

type FilterLevel = 'all' | SeverityLevel;

const moduleIcons: Record<string, keyof typeof Ionicons.glyphMap> = {
  permissions: 'lock-closed',
  behavior: 'pulse',
  signature: 'flash',
  network: 'globe',
  integrity: 'shield-checkmark',
  adware: 'eye',
  exfiltration: 'cloud-upload',
  fraud: 'diamond',
  correlation: 'git-merge',
  'file-scanner': 'folder-open',
};

const FILTER_OPTIONS: { id: FilterLevel; label: string; color: string }[] = [
  { id: 'all', label: 'All', color: colors.textSecondary },
  { id: 'critical', label: 'Critical', color: colors.severity.critical },
  { id: 'high', label: 'High', color: colors.severity.high },
  { id: 'medium', label: 'Medium', color: colors.severity.medium },
  { id: 'low', label: 'Low', color: colors.severity.low },
];

// ─── Module Row ─────────────────────────────────────────────────
function ModuleRow({ module, isActive }: { module: ScanModule; isActive: boolean }) {
  const iconName = moduleIcons[module.id] || 'help-circle';
  return (
    <View style={[styles.moduleRow, isActive && { borderColor: module.accentColor, borderWidth: 1 }]}>
      <View style={styles.moduleRowLeft}>
        <View style={[styles.moduleIconDot, { backgroundColor: module.accentColor + '25' }]}>
          <Ionicons name={iconName} size={16} color={module.accentColor} />
        </View>
        <View style={styles.moduleRowText}>
          <Text style={styles.moduleName}>{module.name}</Text>
          {module.status === 'complete' && (
            <Text style={[styles.moduleFindings, { color: colors.textMuted }]}>
              {module.findingsCount} finding{module.findingsCount !== 1 ? 's' : ''}
            </Text>
          )}
        </View>
      </View>
      <View style={styles.moduleRowRight}>
        {module.status === 'queued' && <Text style={styles.moduleStatusText}>Queued</Text>}
        {module.status === 'scanning' && (
          <View style={styles.scanningIndicator}>
            <ActivityIndicator size="small" color={module.accentColor} />
            <Text style={[styles.moduleStatusText, { color: module.accentColor }]}>{module.progress || 0}%</Text>
          </View>
        )}
        {module.status === 'complete' && <Ionicons name="checkmark-circle" size={20} color={colors.accentSuccess} />}
        {module.status === 'error' && <Ionicons name="alert-circle" size={20} color={colors.accentDanger} />}
      </View>
    </View>
  );
}

// ─── Simple Result Card (no checkboxes) ─────────────────────────
function ResultCard({ result }: { result: ScanResult }) {
  const [expanded, setExpanded] = useState(false);

  const networkGeo = result.moduleId === 'network' && result.evidence
    ? (() => {
        const remote = result.evidence.find((e) => e.startsWith('Remote:'));
        if (remote) {
          const ip = remote.replace('Remote:', '').trim().split(':')[0];
          return estimateIPGeo(ip);
        }
        return null;
      })()
    : null;

  const isRecurrent = result.title.startsWith('[RECURRENT]');

  return (
    <TouchableOpacity onPress={() => setExpanded(!expanded)} activeOpacity={0.8}>
      <GlassCard
        style={[styles.resultCard, isRecurrent && styles.resultCardRecurrent]}
        accentColor={colors.severity[result.severity]}
      >
        {/* Header */}
        <View style={styles.resultHeader}>
          <View style={{ flex: 1 }}>
            <Text style={styles.resultTitle}>
              {result.correlated ? '🔗 ' : ''}{result.title}
            </Text>
            <Text style={styles.resultDesc}>{result.description}</Text>
          </View>
          <View style={styles.badgeStack}>
            <SeverityBadge severity={result.severity} />
            {result.confidence != null && (
              <View style={styles.confidenceBadge}>
                <Text style={styles.confidenceText}>{result.confidence}%</Text>
              </View>
            )}
          </View>
        </View>

        {/* Network geo badge */}
        {networkGeo && networkGeo.region !== 'Unknown' && (
          <View style={styles.geoBadge}>
            <Ionicons name="location" size={12} color={colors.accentInfo} />
            <Text style={styles.geoText}>
              {networkGeo.region} ({networkGeo.country})
            </Text>
          </View>
        )}

        {/* Expand icon hint */}
        <View style={styles.expandHint}>
          <Ionicons
            name={expanded ? 'chevron-up' : 'chevron-down'}
            size={14}
            color={colors.textMuted}
          />
        </View>

        {/* Expanded details */}
        {expanded && (
          <View style={styles.resultExpanded}>
            {result.moduleId === 'network' && networkGeo && (
              <View style={styles.resultSection}>
                <Text style={styles.resultSectionLabel}>ORIGIN</Text>
                <Text style={styles.resultOriginText}>
                  Region: {networkGeo.region} · {networkGeo.note}
                </Text>
              </View>
            )}

            {result.timestamp && (
              <View style={styles.resultSection}>
                <Text style={styles.resultSectionLabel}>FIRST DETECTED</Text>
                <Text style={styles.resultOriginText}>
                  {new Date(result.timestamp).toLocaleString()}
                </Text>
              </View>
            )}

            {result.moduleId && (
              <View style={styles.resultSection}>
                <Text style={styles.resultSectionLabel}>MODULE</Text>
                <Text style={styles.resultOriginText}>{result.moduleId}</Text>
              </View>
            )}

            <View style={styles.resultSection}>
              <Text style={styles.resultSectionLabel}>RECOMMENDATION</Text>
              <Text style={styles.resultRecommendation}>{result.recommendation}</Text>
            </View>

            {result.evidence && result.evidence.length > 0 && (
              <View style={styles.resultSection}>
                <Text style={styles.resultSectionLabel}>EVIDENCE</Text>
                {result.evidence.map((ev, i) => (
                  <View key={i} style={styles.evidenceRow}>
                    <View style={styles.evidenceDot} />
                    <Text style={styles.evidenceText}>{ev}</Text>
                  </View>
                ))}
              </View>
            )}

            {result.packageName && (
              <View style={styles.resultSection}>
                <Text style={styles.resultSectionLabel}>PACKAGE</Text>
                <Text style={styles.packageName}>{result.packageName}</Text>
              </View>
            )}
          </View>
        )}
      </GlassCard>
    </TouchableOpacity>
  );
}

// ─── Cleanup Overlay ─────────────────────────────────────────────
function CleanupOverlay({
  progress,
  onDone,
}: {
  progress: CleanupProgress;
  onDone: () => void;
}) {
  const pulseAnim = useRef(new Animated.Value(1)).current;

  useEffect(() => {
    if (!progress.isComplete) {
      const loop = Animated.loop(
        Animated.sequence([
          Animated.timing(pulseAnim, { toValue: 0.4, duration: 600, useNativeDriver: true }),
          Animated.timing(pulseAnim, { toValue: 1, duration: 600, useNativeDriver: true }),
        ]),
      );
      loop.start();
      return () => loop.stop();
    } else {
      pulseAnim.setValue(1);
    }
  }, [progress.isComplete, pulseAnim]);

  return (
    <View style={styles.cleanupOverlay}>
      <View style={styles.cleanupContent}>
        {/* Header */}
        <View style={styles.cleanupHeader}>
          {progress.isComplete ? (
            <Ionicons name="checkmark-circle" size={40} color={colors.accentSuccess} />
          ) : (
            <Animated.View style={{ opacity: pulseAnim }}>
              <Ionicons name="shield-checkmark" size={40} color={colors.accentMint} />
            </Animated.View>
          )}
          <Text style={styles.cleanupTitle}>
            {progress.isComplete ? 'Cleanup Complete' : 'Cleaning Threats...'}
          </Text>
          <Text style={styles.cleanupSubtitle}>{progress.currentAction}</Text>
        </View>

        {/* Progress bar */}
        <View style={styles.cleanupProgressTrack}>
          <View style={[styles.cleanupProgressFill, { width: `${progress.overallProgress}%` }]} />
        </View>
        <Text style={styles.cleanupPercent}>{progress.overallProgress}%</Text>

        {/* Steps list */}
        <ScrollView style={styles.cleanupStepsList} showsVerticalScrollIndicator={false}>
          {progress.steps.map((step, idx) => (
            <View key={step.id} style={styles.cleanupStepRow}>
              <View style={styles.cleanupStepIcon}>
                {step.status === 'done' && (
                  <Ionicons name="checkmark-circle" size={18} color={colors.accentSuccess} />
                )}
                {step.status === 'failed' && (
                  <Ionicons name="close-circle" size={18} color={colors.accentDanger} />
                )}
                {step.status === 'running' && (
                  <Animated.View style={{ opacity: pulseAnim }}>
                    <Ionicons name={step.icon as keyof typeof Ionicons.glyphMap} size={18} color={colors.accentMint} />
                  </Animated.View>
                )}
                {step.status === 'pending' && (
                  <Ionicons name="ellipse-outline" size={18} color={colors.textMuted} />
                )}
              </View>
              <View style={styles.cleanupStepText}>
                <Text style={[
                  styles.cleanupStepAction,
                  step.status === 'done' && { color: colors.textMuted },
                  step.status === 'running' && { color: colors.accentMint },
                ]}>
                  {step.action}
                </Text>
                <Text style={styles.cleanupStepDetail}>{step.detail}</Text>
              </View>
            </View>
          ))}
        </ScrollView>

        {/* Done button */}
        {progress.isComplete && (
          <TouchableOpacity style={styles.cleanupDoneBtn} onPress={onDone}>
            <Text style={styles.cleanupDoneBtnText}>Done</Text>
          </TouchableOpacity>
        )}
      </View>
    </View>
  );
}

// ─── Main Screen ────────────────────────────────────────────────
export default function ScannerScreen() {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const {
    scanState, currentModuleIndex, modules, overallProgress,
    results, riskScore, report, startScan, resetScan, removeCleanedResults, fileScanProgress
  } = useScanEngine();

  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([]);
  const [exporting, setExporting] = useState(false);
  const [filterLevel, setFilterLevel] = useState<FilterLevel>('all');
  const [aiResult, setAiResult] = useState<AIAnalysisResult | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiConsented, setAiConsented] = useState(false);

  // Cleanup state
  const [showCleanupPicker, setShowCleanupPicker] = useState(false);
  const [showCleanup, setShowCleanup] = useState(false);
  const [cleanupProgress, setCleanupProgress] = useState<CleanupProgress | null>(null);

  // Recurrence state
  const [recurrentCount, setRecurrentCount] = useState(0);
  const [processedResults, setProcessedResults] = useState<ScanResult[]>([]);

  // Load scan history + AI consent status
  useEffect(() => {
    getScanHistory().then(setScanHistory).catch(console.warn);
    Promise.all([getAIConfig(), getOfflineAIConfig()]).then(([cloudCfg, offlineCfg]) => {
      setAiConsented(cloudCfg.consentGiven || offlineCfg.enabled);
    }).catch(() => {});
  }, []);

  // When scan completes, just refresh history. File scanning is now a native engine module.
  useEffect(() => {
    if (scanState === 'complete') {
      getScanHistory().then(setScanHistory).catch(console.warn);
    }
  }, [scanState]);

  // Combine results and detect recurrence
  useEffect(() => {
    if (scanState === 'complete') {
      detectRecurrence(results).then(({ results: flagged, recurrentCount: rc }) => {
        setProcessedResults(flagged);
        setRecurrentCount(rc);
      }).catch(() => {
        setProcessedResults(results);
      });
    }
  }, [scanState, results]);

  // Filter results
  const filteredResults = filterLevel === 'all'
    ? processedResults
    : processedResults.filter((r) => r.severity === filterLevel);

  // Severity breakdown
  const severityBreakdown = {
    critical: processedResults.filter((r) => r.severity === 'critical').length,
    high: processedResults.filter((r) => r.severity === 'high').length,
    medium: processedResults.filter((r) => r.severity === 'medium').length,
    low: processedResults.filter((r) => r.severity === 'low').length,
  };

  // Cleanup handlers
  const handleStartCleanup = useCallback(async () => {
    setShowCleanup(true);
    // Directly execute Deep Clean for 1-click remediation
    const { cleaned } = await executeCleanup('deep', processedResults, (progress) => {
      setCleanupProgress(progress);
    });
  }, [processedResults]);

  const handleCleanupDone = useCallback(() => {
    setShowCleanup(false);
    setCleanupProgress(null);
    // Remove the cleaned results from the state so they disappear from the list
    const cleanedIds = processedResults.map(r => r.id);
    removeCleanedResults(cleanedIds);
    // Force reset recurrence count for removed items
    setProcessedResults([]);
    setRecurrentCount(0);
  }, [processedResults, removeCleanedResults]);

  // Export handlers
  const handleShareText = useCallback(async () => {
    if (!report) return;
    try { setExporting(true); await shareReport(report, 'txt'); }
    catch { Alert.alert('Share Failed', 'Unable to share report.'); }
    finally { setExporting(false); }
  }, [report]);

  const handleShareHTML = useCallback(async () => {
    if (!report) return;
    try { setExporting(true); await shareReport(report, 'html'); }
    catch { Alert.alert('Share Failed', 'Unable to share HTML report.'); }
    finally { setExporting(false); }
  }, [report]);

  const handleExportJSON = useCallback(async () => {
    if (!report) return;
    try { setExporting(true); const path = await saveReportToFile(report, 'json'); Alert.alert('Exported', `Report saved to:\n${path}`); }
    catch { Alert.alert('Export Failed', 'Unable to save JSON report.'); }
    finally { setExporting(false); }
  }, [report]);

  // AI handler
  const handleAIAnalysis = useCallback(async () => {
    if (processedResults.length === 0) return;
    try {
      setAiLoading(true);
      const offlineResult = await analyzeOffline(processedResults, riskScore);
      if (offlineResult && !offlineResult.error) {
        setAiResult(offlineResult);
        setAiLoading(false);
        return;
      }
      const result = await aiAnalyzeFindings(processedResults, riskScore);
      setAiResult(result);
    } catch {
      Alert.alert('AI Analysis Failed', 'Could not connect to AI providers.');
    } finally {
      setAiLoading(false);
    }
  }, [processedResults, riskScore]);

  const isIdle = scanState === 'idle';
  const isRunning = scanState === 'running';
  const isComplete = scanState === 'complete';

  return (
    <View style={styles.container}>
      <ScrollView style={styles.scrollContainer} contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
        {/* ── Hero / Start ─────────────────────────────────────── */}
        <View style={[styles.hero, !isIdle && styles.heroCompact]}>
          <View style={styles.accentBar} />
          <Text style={styles.heroTitle}>Security Scanner</Text>
          <Text style={styles.heroSubtitle}>
            Multi-engine analysis with file scanning. All processing is local.
          </Text>
          <View style={styles.buttonContainer}>
            <ScanButton
              onPress={isComplete ? resetScan : startScan}
              isScanning={isRunning}
              isComplete={isComplete}
              disabled={isRunning}
            />
          </View>
        </View>

        {/* ── Progress ─────────────────────────────────────────── */}
        {isRunning && (
          <View style={styles.progressSection}>
            <View style={styles.progressBarContainer}>
              <View style={styles.progressBarHeader}>
                <Text style={styles.progressLabel}>Scanning...</Text>
                <Text style={styles.progressPercent}>{overallProgress}%</Text>
              </View>
              <View style={styles.progressTrack}>
                <View style={[styles.progressFill, { width: `${overallProgress}%` }]} />
              </View>
            </View>
            <View style={styles.progressContent}>
              <ProgressRing progress={overallProgress} size={140} strokeWidth={10} color={colors.accentMint} label="PROGRESS" />
              <View style={styles.moduleList}>
                {modules.map((mod, idx) => (
                  <ModuleRow key={mod.id} module={mod} isActive={idx === currentModuleIndex} />
                ))}
              </View>
            </View>
          </View>
        )}

        {/* ── File Scan Progress ───────────────────────────────── */}
        {isRunning && fileScanProgress && (
          <View style={styles.fileProgressSection}>
            <GlassCard style={styles.fileProgressCard}>
              <View style={styles.fileProgressHeader}>
                <Ionicons name="folder-open" size={20} color={colors.accentInfo} />
                <Text style={styles.fileProgressTitle}>Deep File Scan</Text>
              </View>
              
              <View style={styles.fileProgressStats}>
                <View style={styles.statBox}>
                  <Text style={styles.statValue}>{fileScanProgress.filesScanned}</Text>
                  <Text style={styles.statLabel}>Files</Text>
                </View>
                <View style={styles.statBox}>
                  <Text style={[styles.statValue, fileScanProgress.threatsFound > 0 && { color: colors.accentDanger }]}>
                    {fileScanProgress.threatsFound}
                  </Text>
                  <Text style={styles.statLabel}>Threats</Text>
                </View>
                <View style={styles.statBox}>
                  <Text style={styles.statValue}>{fileScanProgress.progress}%</Text>
                  <Text style={styles.statLabel}>Done</Text>
                </View>
              </View>
              
              <Text style={styles.fileProgressPath} numberOfLines={1} ellipsizeMode="middle">
                {fileScanProgress.currentFolder}
              </Text>
              {fileScanProgress.deepAnalysisActive && (
                <Text style={styles.deepScanLabel}>
                  <Ionicons name="medical" size={12} color={colors.accentMint} /> Binary Analysis Active
                </Text>
              )}
            </GlassCard>
          </View>
        )}

        {/* ── Results Section ──────────────────────────────────── */}
        {isComplete && processedResults.length > 0 && (
          <View style={styles.resultsSection}>
            {/* Recurrence Banner */}
            {recurrentCount > 0 && (
              <GlassCard style={styles.recurrenceBanner} accentColor={colors.accentDanger}>
                <View style={styles.recurrenceContent}>
                  <Ionicons name="warning" size={20} color={colors.accentDanger} />
                  <View style={styles.recurrenceTextContainer}>
                    <Text style={styles.recurrenceTitle}>
                      {recurrentCount} Recurrent Threat{recurrentCount > 1 ? 's' : ''} Detected
                    </Text>
                    <Text style={styles.recurrenceDesc}>
                      These threats reappeared after previous cleanup. They may have persistence mechanisms.
                    </Text>
                  </View>
                </View>
              </GlassCard>
            )}

            {/* Summary Card */}
            <GlassCard style={styles.summaryCard}>
              <Text style={styles.summaryTitle}>
                {processedResults.length} Threat{processedResults.length !== 1 ? 's' : ''} Found
              </Text>
              <View style={styles.summaryBreakdown}>
                {severityBreakdown.critical > 0 && (
                  <View style={styles.summaryPill}>
                    <View style={[styles.summaryDot, { backgroundColor: colors.severity.critical }]} />
                    <Text style={styles.summaryPillText}>{severityBreakdown.critical} Critical</Text>
                  </View>
                )}
                {severityBreakdown.high > 0 && (
                  <View style={styles.summaryPill}>
                    <View style={[styles.summaryDot, { backgroundColor: colors.severity.high }]} />
                    <Text style={styles.summaryPillText}>{severityBreakdown.high} High</Text>
                  </View>
                )}
                {severityBreakdown.medium > 0 && (
                  <View style={styles.summaryPill}>
                    <View style={[styles.summaryDot, { backgroundColor: colors.severity.medium }]} />
                    <Text style={styles.summaryPillText}>{severityBreakdown.medium} Medium</Text>
                  </View>
                )}
                {severityBreakdown.low > 0 && (
                  <View style={styles.summaryPill}>
                    <View style={[styles.summaryDot, { backgroundColor: colors.severity.low }]} />
                    <Text style={styles.summaryPillText}>{severityBreakdown.low} Low</Text>
                  </View>
                )}
              </View>
              {(() => {
                const fileScanCount = processedResults.filter((r) => r.moduleId === 'file_scanner').length;
                return fileScanCount > 0 ? (
                  <Text style={styles.summaryFileScan}>
                    Includes {fileScanCount} file scan finding{fileScanCount !== 1 ? 's' : ''}
                  </Text>
                ) : null;
              })()}
            </GlassCard>

            {/* Filter Pills */}
            <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.filterScroll}>
              <View style={styles.filterRow}>
                {FILTER_OPTIONS.map((opt) => {
                  const count = opt.id === 'all'
                    ? processedResults.length
                    : processedResults.filter((r) => r.severity === opt.id).length;
                  return (
                    <TouchableOpacity
                      key={opt.id}
                      style={[styles.filterPill, filterLevel === opt.id && styles.filterPillActive]}
                      onPress={() => setFilterLevel(opt.id)}
                    >
                      <Text style={[styles.filterPillText, filterLevel === opt.id && { color: opt.color }]}>
                        {opt.label} ({count})
                      </Text>
                    </TouchableOpacity>
                  );
                })}
              </View>
            </ScrollView>

            {/* Threat List */}
            {filteredResults.map((result) => (
              <ResultCard key={result.id} result={result} />
            ))}

            {/* Handle All Threats Button (1-Click) */}
            <TouchableOpacity
              style={styles.handleAllButton}
              onPress={handleStartCleanup}
              activeOpacity={0.85}
            >
              <Ionicons name="shield-checkmark" size={22} color={colors.bgDeep} />
              <Text style={styles.handleAllButtonText}>Clean Up All Threats</Text>
            </TouchableOpacity>
          </View>
        )}

        {/* ── Cleanup Overlay ────────────────────────────────────── */}
        {showCleanup && cleanupProgress && (
          <CleanupOverlay
            progress={cleanupProgress}
            onDone={handleCleanupDone}
          />
        )}

        {/* ── AI Analysis ──────────────────────────────────────── */}
        {isComplete && aiConsented && processedResults.length > 0 && (
          <View style={styles.aiSection}>
            <View style={styles.sectionDivider}>
              <View style={styles.dividerLine} />
              <Text style={styles.dividerLabel}>AI ANALYSIS</Text>
              <View style={styles.dividerLine} />
            </View>

            {!aiResult && !aiLoading && (
              <TouchableOpacity style={styles.aiButton} onPress={handleAIAnalysis}>
                <Ionicons name="sparkles" size={18} color={colors.bgDeep} />
                <Text style={styles.aiButtonText}>Run AI Analysis</Text>
              </TouchableOpacity>
            )}

            {aiLoading && (
              <GlassCard style={styles.aiLoadingCard}>
                <ActivityIndicator size="small" color={colors.accentWarning} />
                <Text style={styles.aiLoadingText}>Analyzing findings with AI...</Text>
              </GlassCard>
            )}

            {aiResult && (
              <GlassCard style={styles.aiResultCard} accentColor={colors.accentWarning}>
                <View style={styles.aiResultHeader}>
                  <Ionicons name="sparkles" size={18} color={colors.accentWarning} />
                  <Text style={styles.aiResultTitle}>AI Analysis</Text>
                  <View style={styles.aiProviderBadge}>
                    <Text style={styles.aiProviderText}>{aiResult.provider} · {aiResult.model}</Text>
                  </View>
                </View>

                {aiResult.error ? (
                  <Text style={styles.aiErrorText}>{aiResult.error}</Text>
                ) : (
                  <>
                    <Text style={styles.aiSummary}>{aiResult.summary}</Text>

                    {aiResult.overallAssessment ? (
                      <View style={styles.aiAssessment}>
                        <Text style={styles.aiAssessmentLabel}>ASSESSMENT</Text>
                        <Text style={styles.aiAssessmentText}>{aiResult.overallAssessment}</Text>
                      </View>
                    ) : null}

                    {aiResult.insights.length > 0 && (
                      <View style={styles.aiInsights}>
                        <Text style={styles.aiInsightsLabel}>TOP INSIGHTS</Text>
                        {aiResult.insights.slice(0, 5).map((insight, idx) => (
                          <View key={idx} style={styles.aiInsightRow}>
                            <View style={[styles.aiPriorityDot, {
                              backgroundColor:
                                insight.priority === 'immediate' ? colors.accentDanger :
                                insight.priority === 'high' ? colors.accentOrange :
                                insight.priority === 'moderate' ? colors.accentWarning :
                                colors.accentInfo,
                            }]} />
                            <View style={styles.aiInsightContent}>
                              <Text style={styles.aiInsightAnalysis}>{insight.analysis}</Text>
                              {insight.attackVector ? (
                                <Text style={styles.aiInsightVector}>Attack vector: {insight.attackVector}</Text>
                              ) : null}
                              {insight.remediationSteps.length > 0 && (
                                <View style={styles.aiRemediationList}>
                                  {insight.remediationSteps.map((step, si) => (
                                    <Text key={si} style={styles.aiRemediationStep}>
                                      {si + 1}. {step}
                                    </Text>
                                  ))}
                                </View>
                              )}
                            </View>
                          </View>
                        ))}
                      </View>
                    )}
                  </>
                )}

                <TouchableOpacity
                  style={styles.aiRerunBtn}
                  onPress={handleAIAnalysis}
                  disabled={aiLoading}
                >
                  <Ionicons name="refresh" size={14} color={colors.accentWarning} />
                  <Text style={styles.aiRerunText}>Re-analyze</Text>
                </TouchableOpacity>
              </GlassCard>
            )}
          </View>
        )}

        {/* ── Risk Score ───────────────────────────────────────── */}
        {isComplete && riskScore && (
          <View style={styles.riskSection}>
            <GlassCard style={styles.riskCard}>
              <Text style={styles.riskTitle}>Risk Assessment</Text>
              <View style={styles.riskRingContainer}>
                <ProgressRing progress={riskScore.overall} size={160} strokeWidth={12} />
              </View>
              <Text style={[styles.riskLevel, { color: colors.severity[riskScore.level] }]}>
                {riskScore.level.toUpperCase()} RISK
              </Text>
              <Text style={styles.riskSummary}>{riskScore.summary}</Text>
              <View style={styles.breakdownContainer}>
                {Object.entries(riskScore.breakdown).map(([key, value]) => (
                  <View key={key} style={styles.breakdownRow}>
                    <View style={styles.breakdownLeft}>
                      <View style={[styles.breakdownDot, { backgroundColor: colors.textMuted }]} />
                      <Text style={styles.breakdownLabel}>{key.charAt(0).toUpperCase() + key.slice(1)}</Text>
                    </View>
                    <View style={styles.breakdownBarTrack}>
                      <View style={[styles.breakdownBarFill, {
                        width: `${value}%`,
                        backgroundColor: value > 75 ? colors.accentDanger : value > 50 ? colors.accentWarning : value > 25 ? colors.accentInfo : colors.accentSuccess,
                      }]} />
                    </View>
                    <Text style={styles.breakdownValue}>{value}</Text>
                  </View>
                ))}
              </View>
            </GlassCard>
          </View>
        )}

        {/* ── Export ────────────────────────────────────────────── */}
        {isComplete && report && (
          <View style={styles.exportSection}>
            <View style={styles.sectionDivider}>
              <View style={styles.dividerLine} />
              <Text style={styles.dividerLabel}>EXPORT REPORT</Text>
              <View style={styles.dividerLine} />
            </View>
            <View style={styles.exportButtons}>
              <TouchableOpacity style={styles.exportBtn} onPress={handleShareText} disabled={exporting}>
                <Ionicons name="share-outline" size={18} color={colors.accentMint} />
                <Text style={styles.exportBtnText}>Share Text</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.exportBtn} onPress={handleShareHTML} disabled={exporting}>
                <Ionicons name="document-text-outline" size={18} color={colors.accentInfo} />
                <Text style={[styles.exportBtnText, { color: colors.accentInfo }]}>Share HTML</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.exportBtn} onPress={handleExportJSON} disabled={exporting}>
                <Ionicons name="code-slash-outline" size={18} color={colors.accentWarning} />
                <Text style={[styles.exportBtnText, { color: colors.accentWarning }]}>Save JSON</Text>
              </TouchableOpacity>
            </View>
            {exporting && (
              <View style={styles.exportingRow}>
                <ActivityIndicator size="small" color={colors.accentMint} />
                <Text style={styles.exportingText}>Preparing report...</Text>
              </View>
            )}

            {/* Ask AI about results */}
            {processedResults.length > 0 && (
              <TouchableOpacity
                style={styles.askAiBtn}
                onPress={() => navigation.navigate('AiAgentScreen')}
              >
                <Ionicons name="hardware-chip" size={18} color={colors.bgDeep} />
                <Text style={styles.askAiBtnText}>Ask AI About These Results</Text>
              </TouchableOpacity>
            )}
          </View>
        )}

        {/* ── Scan History ─────────────────────────────────────── */}
        <View style={styles.historySection}>
          <View style={styles.historyHeader}>
            <Ionicons name="time" size={16} color={colors.textMuted} />
            <Text style={styles.historyTitle}>Scan History</Text>
            <View style={styles.dividerLine} />
          </View>
          {scanHistory.length === 0 && (
            <GlassCard style={styles.historyCard}>
              <Text style={styles.historyEmpty}>No scan history yet. Run your first scan above.</Text>
            </GlassCard>
          )}
          {scanHistory.slice(0, 10).map((record) => {
            const level = (record.riskLevel || 'low') as keyof typeof colors.severity;
            const statusLabel = record.criticalCount > 0 ? 'Critical' : record.highCount > 0 ? 'Warnings' : 'Safe';
            return (
              <GlassCard key={record.id} style={styles.historyCard}>
                <View style={styles.historyCardContent}>
                  <View style={styles.historyLeft}>
                    <View style={[styles.historyIcon, { backgroundColor: (colors.severity[level] || colors.textMuted) + '20' }]}>
                      <Ionicons name={level === 'low' || level === 'safe' ? 'checkmark-circle' : 'warning'} size={16} color={colors.severity[level] || colors.textMuted} />
                    </View>
                    <View>
                      <Text style={styles.historyDate}>{new Date(record.timestamp).toLocaleDateString()}</Text>
                      <Text style={styles.historyScore}>Score: {record.riskScore} · {record.findingsCount} finding{record.findingsCount !== 1 ? 's' : ''}</Text>
                    </View>
                  </View>
                  <View style={styles.historyRight}>
                    <View style={[styles.historyBadge, { backgroundColor: (colors.severity[level] || colors.textMuted) + '20' }]}>
                      <Text style={[styles.historyBadgeText, { color: colors.severity[level] || colors.textMuted }]}>{statusLabel}</Text>
                    </View>
                    <Ionicons name="chevron-forward" size={14} color={colors.textMuted} />
                  </View>
                </View>
              </GlassCard>
            );
          })}
        </View>

        <View style={{ height: 40 }} />
      </ScrollView>

      {/* ── Cleanup Overlay (rendered above scroll) ─────────── */}
      {showCleanup && cleanupProgress && (
        <CleanupOverlay progress={cleanupProgress} onDone={handleCleanupDone} />
      )}
    </View>
  );
}

// ─── Styles ─────────────────────────────────────────────────────
const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgDeep },
  scrollContainer: { flex: 1 },
  content: { paddingBottom: 40 },

  // Hero
  hero: { paddingHorizontal: spacing.lg, paddingTop: 60, paddingBottom: 30, alignItems: 'center' },
  heroCompact: { paddingTop: 30, paddingBottom: 20 },
  accentBar: { width: 64, height: 4, borderRadius: 2, marginBottom: 24, backgroundColor: colors.accentMint },
  heroTitle: { fontSize: 28, fontWeight: '700', color: colors.textPrimary, textAlign: 'center', letterSpacing: -0.5, marginBottom: 12 },
  heroSubtitle: { fontSize: 15, color: colors.textSecondary, textAlign: 'center', lineHeight: 22, maxWidth: 400, marginBottom: 24 },
  buttonContainer: { marginBottom: 20 },

  // Progress
  progressSection: { paddingHorizontal: spacing.lg, paddingBottom: 20 },
  progressBarContainer: { marginBottom: 24 },
  progressBarHeader: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 },
  progressLabel: { fontFamily: 'monospace', fontSize: 12, color: colors.accentMint },
  progressPercent: { fontFamily: 'monospace', fontSize: 12, color: colors.accentMint },
  progressTrack: { height: 8, borderRadius: 4, backgroundColor: colors.bgSurface, overflow: 'hidden' },
  progressFill: { height: '100%', borderRadius: 4, backgroundColor: colors.accentMint },
  progressContent: { alignItems: 'center', gap: 24 },
  moduleList: { width: '100%', gap: 8 },

  // Module
  moduleRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', backgroundColor: colors.bgGlass, borderRadius: borderRadius.md, padding: 12, borderWidth: 1, borderColor: 'transparent' },
  moduleRowLeft: { flexDirection: 'row', alignItems: 'center', gap: 12 },
  moduleIconDot: { width: 36, height: 36, borderRadius: 10, alignItems: 'center', justifyContent: 'center' },
  moduleRowText: { gap: 2 },
  moduleName: { fontSize: 14, fontWeight: '600', color: colors.textPrimary },
  moduleFindings: { fontFamily: 'monospace', fontSize: 10 },
  moduleRowRight: { flexDirection: 'row', alignItems: 'center' },
  scanningIndicator: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  moduleStatusText: { fontFamily: 'monospace', fontSize: 11, color: colors.textMuted },

  // File scan
  fileScanSection: { paddingHorizontal: spacing.lg, paddingBottom: 12 },
  fileScanCard: { padding: 14 },
  fileScanHeader: { flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 10 },
  fileScanText: { fontSize: 13, color: colors.textSecondary },
  
  fileProgressSection: { paddingHorizontal: spacing.lg, paddingBottom: 16 },
  fileProgressCard: { padding: 18 },
  fileProgressHeader: { flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 16 },
  fileProgressTitle: { fontSize: 16, fontWeight: '700', color: colors.textPrimary },
  fileProgressStats: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 16 },
  statBox: { alignItems: 'center', flex: 1 },
  statValue: { fontSize: 20, fontWeight: '700', color: colors.textPrimary, fontFamily: 'monospace' },
  statLabel: { fontSize: 11, color: colors.textMuted, marginTop: 4, letterSpacing: 0.5, textTransform: 'uppercase' },
  fileProgressPath: { fontSize: 11, color: colors.textSecondary, fontFamily: 'monospace', backgroundColor: colors.bgDeep, padding: 8, borderRadius: borderRadius.sm, overflow: 'hidden' },
  deepScanLabel: { marginTop: 10, fontSize: 11, color: colors.accentMint, fontFamily: 'monospace', textAlign: 'center' },

  // Results
  resultsSection: { paddingHorizontal: spacing.lg, paddingTop: 10, gap: 10 },
  sectionDivider: { flexDirection: 'row', alignItems: 'center', gap: 12, marginBottom: 8 },
  dividerLine: { flex: 1, height: 1, backgroundColor: colors.glassBorder },
  dividerLabel: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted, letterSpacing: 1.5 },

  // Recurrence Banner
  recurrenceBanner: { padding: 14, marginBottom: 4 },
  recurrenceContent: { flexDirection: 'row', alignItems: 'flex-start', gap: 12 },
  recurrenceTextContainer: { flex: 1 },
  recurrenceTitle: { fontSize: 14, fontWeight: '700', color: colors.accentDanger, marginBottom: 4 },
  recurrenceDesc: { fontSize: 12, color: colors.textSecondary, lineHeight: 17 },

  // Summary Card
  summaryCard: { padding: 18, alignItems: 'center' },
  summaryTitle: { fontSize: 20, fontWeight: '700', color: colors.textPrimary, marginBottom: 12 },
  summaryBreakdown: { flexDirection: 'row', flexWrap: 'wrap', gap: 8, justifyContent: 'center' },
  summaryPill: { flexDirection: 'row', alignItems: 'center', gap: 6, paddingHorizontal: 10, paddingVertical: 4, borderRadius: borderRadius.full, backgroundColor: colors.bgSurface },
  summaryDot: { width: 8, height: 8, borderRadius: 4 },
  summaryPillText: { fontSize: 12, fontWeight: '600', color: colors.textSecondary },
  summaryFileScan: { marginTop: 10, fontSize: 11, color: colors.textMuted, fontFamily: 'monospace' },

  // Filter
  filterScroll: { marginBottom: 8 },
  filterRow: { flexDirection: 'row', gap: 8 },
  filterPill: { paddingHorizontal: 14, paddingVertical: 6, borderRadius: borderRadius.full, borderWidth: 1, borderColor: colors.glassBorder },
  filterPillActive: { backgroundColor: colors.accentMint + '15', borderColor: colors.accentMint + '40' },
  filterPillText: { fontSize: 12, fontWeight: '600', color: colors.textSecondary },

  // Result Card
  resultCard: { padding: 14 },
  resultCardRecurrent: { borderWidth: 1, borderColor: colors.accentDanger + '50' },
  resultHeader: { flexDirection: 'row', alignItems: 'flex-start', gap: 10 },
  resultTitle: { fontSize: 14, fontWeight: '600', color: colors.textPrimary, marginBottom: 4 },
  resultDesc: { fontSize: 13, color: colors.textSecondary, lineHeight: 18 },
  expandHint: { alignItems: 'center', marginTop: 6 },

  // Badge stack
  badgeStack: { alignItems: 'flex-end', gap: 4 },
  confidenceBadge: { paddingHorizontal: 6, paddingVertical: 2, borderRadius: borderRadius.sm, backgroundColor: colors.accentInfo + '20' },
  confidenceText: { fontFamily: 'monospace', fontSize: 9, fontWeight: '700', color: colors.accentInfo },

  // Geo badge
  geoBadge: { flexDirection: 'row', alignItems: 'center', gap: 4, marginTop: 8, paddingHorizontal: 8, paddingVertical: 3, backgroundColor: colors.accentInfo + '15', borderRadius: borderRadius.full, alignSelf: 'flex-start' },
  geoText: { fontSize: 10, color: colors.accentInfo, fontFamily: 'monospace' },

  // Expanded
  resultExpanded: { marginTop: 14, paddingTop: 14, borderTopWidth: 1, borderTopColor: colors.glassBorder, gap: 12 },
  resultSection: { gap: 4 },
  resultSectionLabel: { fontFamily: 'monospace', fontSize: 9, color: colors.textMuted, letterSpacing: 1.5, marginBottom: 4 },
  resultRecommendation: { fontSize: 13, color: colors.accentMint, lineHeight: 18 },
  resultOriginText: { fontSize: 12, color: colors.textSecondary, fontFamily: 'monospace' },
  evidenceRow: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  evidenceDot: { width: 4, height: 4, borderRadius: 2, backgroundColor: colors.textMuted },
  evidenceText: { fontFamily: 'monospace', fontSize: 11, color: colors.textSecondary },
  packageName: { fontFamily: 'monospace', fontSize: 11, color: colors.accentInfo },

  // Handle All Button
  handleAllButton: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 10, paddingVertical: 18, borderRadius: borderRadius.md, backgroundColor: colors.accentMint, marginTop: 12 },
  handleAllButtonText: { fontSize: 17, fontWeight: '700', color: colors.bgDeep },

  // Cleanup Style Picker
  cleanupPickerOverlay: { paddingHorizontal: spacing.lg, paddingTop: 12, paddingBottom: 20 },
  cleanupPickerContent: { backgroundColor: colors.bgSurface, borderRadius: borderRadius.md, padding: 18, borderWidth: 1, borderColor: colors.glassBorder },
  cleanupPickerHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 },
  cleanupPickerTitle: { fontSize: 18, fontWeight: '700', color: colors.textPrimary },
  cleanupStyleCard: { flexDirection: 'row', alignItems: 'center', gap: 14, paddingVertical: 16, paddingHorizontal: 12, borderRadius: borderRadius.md, backgroundColor: colors.bgGlass, marginBottom: 10, borderWidth: 1, borderColor: colors.glassBorder },
  cleanupStyleIcon: { width: 48, height: 48, borderRadius: 12, alignItems: 'center', justifyContent: 'center' },
  cleanupStyleText: { flex: 1 },
  cleanupStyleTitle: { fontSize: 15, fontWeight: '700', marginBottom: 3 },
  cleanupStyleDesc: { fontSize: 12, color: colors.textSecondary, lineHeight: 17 },

  // Cleanup Overlay
  cleanupOverlay: { position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: colors.bgDeep + 'F5', justifyContent: 'center', alignItems: 'center', zIndex: 100 },
  cleanupContent: { width: '90%', maxHeight: '85%', backgroundColor: colors.bgSurface, borderRadius: borderRadius.md, padding: 24, borderWidth: 1, borderColor: colors.glassBorder },
  cleanupHeader: { alignItems: 'center', marginBottom: 24 },
  cleanupTitle: { fontSize: 20, fontWeight: '700', color: colors.textPrimary, marginTop: 12 },
  cleanupSubtitle: { fontSize: 13, color: colors.textSecondary, marginTop: 6, textAlign: 'center' },
  cleanupProgressTrack: { height: 10, borderRadius: 5, backgroundColor: colors.bgGlass, overflow: 'hidden', marginBottom: 6 },
  cleanupProgressFill: { height: '100%', borderRadius: 5, backgroundColor: colors.accentMint },
  cleanupPercent: { fontFamily: 'monospace', fontSize: 12, color: colors.accentMint, textAlign: 'right', marginBottom: 16 },
  cleanupStepsList: { maxHeight: 300 },
  cleanupStepRow: { flexDirection: 'row', alignItems: 'flex-start', gap: 10, paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: colors.glassBorder },
  cleanupStepIcon: { width: 24, alignItems: 'center', paddingTop: 2 },
  cleanupStepText: { flex: 1 },
  cleanupStepAction: { fontSize: 13, fontWeight: '600', color: colors.textPrimary },
  cleanupStepDetail: { fontSize: 11, color: colors.textMuted, marginTop: 2 },
  cleanupDoneBtn: { marginTop: 20, alignItems: 'center', paddingVertical: 14, borderRadius: borderRadius.md, backgroundColor: colors.accentMint },
  cleanupDoneBtnText: { fontSize: 16, fontWeight: '700', color: colors.bgDeep },

  // Risk Score
  riskSection: { paddingHorizontal: spacing.lg, paddingTop: 20 },
  riskCard: { alignItems: 'center', padding: 24 },
  riskTitle: { fontSize: 18, fontWeight: '700', color: colors.textPrimary, marginBottom: 20 },
  riskRingContainer: { marginBottom: 16 },
  riskLevel: { fontFamily: 'monospace', fontSize: 14, fontWeight: '700', letterSpacing: 2, marginBottom: 8 },
  riskSummary: { fontSize: 14, color: colors.textSecondary, textAlign: 'center', lineHeight: 20, marginBottom: 24, maxWidth: 350 },
  breakdownContainer: { width: '100%', gap: 10 },
  breakdownRow: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  breakdownLeft: { flexDirection: 'row', alignItems: 'center', gap: 8, width: 110 },
  breakdownDot: { width: 8, height: 8, borderRadius: 4 },
  breakdownLabel: { fontSize: 12, color: colors.textSecondary },
  breakdownBarTrack: { flex: 1, height: 6, borderRadius: 3, backgroundColor: colors.ringTrack, overflow: 'hidden' },
  breakdownBarFill: { height: '100%', borderRadius: 3 },
  breakdownValue: { fontFamily: 'monospace', fontSize: 11, color: colors.textSecondary, width: 28, textAlign: 'right' },

  // Export
  exportSection: { paddingHorizontal: spacing.lg, paddingTop: 20 },
  exportButtons: { flexDirection: 'row', gap: 10, marginTop: 12 },
  exportBtn: { flex: 1, flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 6, paddingVertical: 16, borderRadius: borderRadius.md, backgroundColor: colors.bgGlass, borderWidth: 1, borderColor: colors.glassBorder },
  exportBtnText: { fontSize: 11, fontWeight: '600', color: colors.accentMint },
  exportingRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8, marginTop: 12 },
  exportingText: { fontSize: 12, color: colors.textMuted, fontStyle: 'italic' },

  // Ask AI button
  askAiBtn: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8, marginTop: 16, paddingVertical: 14, borderRadius: borderRadius.md, backgroundColor: colors.accentMint },
  askAiBtnText: { fontSize: 14, fontWeight: '700', color: colors.bgDeep },

  // AI Analysis
  aiSection: { paddingHorizontal: spacing.lg, paddingTop: 20 },
  aiButton: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8, paddingVertical: 14, borderRadius: borderRadius.md, backgroundColor: colors.accentWarning, marginTop: 12 },
  aiButtonText: { fontSize: 15, fontWeight: '700', color: colors.bgDeep },
  aiLoadingCard: { flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 10, padding: 24, marginTop: 12 },
  aiLoadingText: { fontSize: 14, fontWeight: '600', color: colors.textPrimary },
  aiResultCard: { padding: 18, marginTop: 12 },
  aiResultHeader: { flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 14 },
  aiResultTitle: { fontSize: 16, fontWeight: '700', color: colors.textPrimary, flex: 1 },
  aiProviderBadge: { paddingHorizontal: 8, paddingVertical: 3, borderRadius: borderRadius.full, backgroundColor: colors.accentWarning + '20' },
  aiProviderText: { fontFamily: 'monospace', fontSize: 9, fontWeight: '600', color: colors.accentWarning },
  aiErrorText: { fontSize: 13, color: colors.accentDanger, marginTop: 4, lineHeight: 18 },
  aiSummary: { fontSize: 14, color: colors.textPrimary, lineHeight: 20, marginBottom: 14 },
  aiAssessment: { marginBottom: 14, paddingTop: 12, borderTopWidth: 1, borderTopColor: colors.glassBorder },
  aiAssessmentLabel: { fontFamily: 'monospace', fontSize: 9, color: colors.textMuted, letterSpacing: 1.5, marginBottom: 6 },
  aiAssessmentText: { fontSize: 13, color: colors.textSecondary, lineHeight: 19 },
  aiInsights: { paddingTop: 12, borderTopWidth: 1, borderTopColor: colors.glassBorder },
  aiInsightsLabel: { fontFamily: 'monospace', fontSize: 9, color: colors.textMuted, letterSpacing: 1.5, marginBottom: 10 },
  aiInsightRow: { flexDirection: 'row', gap: 10, marginBottom: 14 },
  aiPriorityDot: { width: 8, height: 8, borderRadius: 4, marginTop: 5 },
  aiInsightContent: { flex: 1 },
  aiInsightAnalysis: { fontSize: 13, color: colors.textPrimary, lineHeight: 18, marginBottom: 4 },
  aiInsightVector: { fontSize: 11, color: colors.accentOrange, fontFamily: 'monospace', lineHeight: 16, marginBottom: 6 },
  aiRemediationList: { gap: 3 },
  aiRemediationStep: { fontSize: 11, color: colors.textSecondary, lineHeight: 16, paddingLeft: 4 },
  aiRerunBtn: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 6, marginTop: 14, paddingVertical: 8, borderRadius: borderRadius.sm, borderWidth: 1, borderColor: colors.accentWarning + '40' },
  aiRerunText: { fontSize: 12, fontWeight: '600', color: colors.accentWarning },

  // History
  historyEmpty: { fontSize: 13, color: colors.textMuted, textAlign: 'center', paddingVertical: 8 },
  historySection: { paddingHorizontal: spacing.lg, paddingTop: 30, gap: 10 },
  historyHeader: { flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 6 },
  historyTitle: { fontSize: 16, fontWeight: '600', color: colors.textPrimary },
  historyCard: { padding: 14 },
  historyCardContent: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  historyLeft: { flexDirection: 'row', alignItems: 'center', gap: 12 },
  historyIcon: { width: 36, height: 36, borderRadius: 10, alignItems: 'center', justifyContent: 'center' },
  historyDate: { fontSize: 14, fontWeight: '500', color: colors.textPrimary },
  historyScore: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted },
  historyRight: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  historyBadge: { paddingHorizontal: 10, paddingVertical: 3, borderRadius: borderRadius.full },
  historyBadgeText: { fontFamily: 'monospace', fontSize: 10, fontWeight: '600' },
});
