import React, { useState } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  TouchableOpacity,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius } from '../theme';
import { useRemediation } from '../hooks/useRemediation';
import { getRemediationStats } from '../data/remediation';
import GlassCard from '../components/common/GlassCard';
import SeverityBadge from '../components/common/SeverityBadge';
import type { RemediationWorkflow, RemediationStep } from '../types/engine';

// ─── Stat Pill ──────────────────────────────────────────────────
function StatPill({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <View style={[styles.statPill, { backgroundColor: color + '15', borderColor: color + '25' }]}>
      <View style={[styles.statDot, { backgroundColor: color }]} />
      <Text style={[styles.statPillText, { color }]}>{count} {label}</Text>
    </View>
  );
}

// ─── Step Row ───────────────────────────────────────────────────
function StepRow({
  step,
  index,
  isCompleted,
  isCurrentStep,
  stepColor,
  onComplete,
}: {
  step: RemediationStep;
  index: number;
  isCompleted: boolean;
  isCurrentStep: boolean;
  stepColor: string;
  onComplete: () => void;
}) {
  const actionLabels: Record<string, string> = {
    uninstall: 'UNINSTALL',
    revoke_permission: 'REVOKE',
    disable_service: 'DISABLE',
    block_network: 'BLOCK',
    manual: 'MANUAL',
    verify: 'VERIFY',
  };

  return (
    <View style={[styles.stepRow, isCurrentStep && styles.stepRowActive]}>
      <View style={styles.stepLeft}>
        <TouchableOpacity
          onPress={onComplete}
          disabled={isCompleted}
          style={[
            styles.stepCheckbox,
            isCompleted && { backgroundColor: colors.accentSuccess, borderColor: colors.accentSuccess },
          ]}
        >
          {isCompleted && <Ionicons name="checkmark" size={14} color={colors.bgDeep} />}
        </TouchableOpacity>

        <View style={styles.stepContent}>
          <View style={styles.stepTitleRow}>
            <Text style={[styles.stepNumber, { color: stepColor }]}>{index + 1}</Text>
            <Text style={[styles.stepTitle, isCompleted && styles.stepTitleComplete]}>
              {step.title}
            </Text>
          </View>
          <Text style={styles.stepDesc}>{step.description}</Text>
          <View style={styles.stepTags}>
            <View style={[styles.actionTag, { backgroundColor: stepColor + '20' }]}>
              <Text style={[styles.actionTagText, { color: stepColor }]}>
                {actionLabels[step.action] || step.action.toUpperCase()}
              </Text>
            </View>
            {step.requiresManualAction && (
              <View style={[styles.actionTag, { backgroundColor: colors.accentWarning + '20' }]}>
                <Text style={[styles.actionTagText, { color: colors.accentWarning }]}>MANUAL</Text>
              </View>
            )}
          </View>
        </View>
      </View>
    </View>
  );
}

// ─── Workflow Card ──────────────────────────────────────────────
function WorkflowCard({
  workflow,
  workflowState,
  onToggleSelect,
  onToggleExpand,
  onMarkStepComplete,
  getStepColor,
}: {
  workflow: RemediationWorkflow;
  workflowState: any;
  onToggleSelect: (id: string) => void;
  onToggleExpand: (id: string) => void;
  onMarkStepComplete: (workflowId: string, stepIndex: number) => void;
  getStepColor: (step: RemediationStep, completed: boolean) => string;
}) {
  return (
    <GlassCard style={styles.workflowCard} accentColor={colors.severity[workflow.severity]}>
      {/* Header */}
      <TouchableOpacity
        style={styles.workflowHeader}
        onPress={() => onToggleExpand(workflow.id)}
        activeOpacity={0.7}
      >
        <TouchableOpacity
          onPress={() => onToggleSelect(workflow.id)}
          style={[
            styles.checkbox,
            workflowState.selected && { backgroundColor: colors.accentMint, borderColor: colors.accentMint },
          ]}
        >
          {workflowState.selected && <Ionicons name="checkmark" size={14} color={colors.bgDeep} />}
        </TouchableOpacity>

        <View style={styles.workflowInfo}>
          <View style={styles.workflowTitleRow}>
            <Text style={styles.workflowTitle}>{workflow.threatName}</Text>
            <SeverityBadge severity={workflow.severity} />
          </View>
          <Text style={styles.workflowCategory}>{workflow.category}</Text>
          <Text style={styles.workflowDesc} numberOfLines={2}>{workflow.description}</Text>
        </View>

        <Ionicons
          name={workflowState.expanded ? 'chevron-up' : 'chevron-down'}
          size={18}
          color={colors.textMuted}
        />
      </TouchableOpacity>

      {/* Expanded Steps */}
      {workflowState.expanded && (
        <View style={styles.stepsContainer}>
          <View style={styles.stepsDivider} />
          <Text style={styles.stepsLabel}>
            REMEDIATION STEPS ({workflow.steps.length})
          </Text>
          {workflow.steps.map((step, idx) => (
            <StepRow
              key={step.id}
              step={step}
              index={idx}
              isCompleted={workflowState.stepsCompleted[idx]}
              isCurrentStep={idx === workflowState.currentStep}
              stepColor={getStepColor(step, workflowState.stepsCompleted[idx])}
              onComplete={() => onMarkStepComplete(workflow.id, idx)}
            />
          ))}

          {/* Progress */}
          <View style={styles.stepProgress}>
            <Text style={styles.stepProgressText}>
              {workflowState.stepsCompleted.filter(Boolean).length} / {workflow.steps.length} complete
            </Text>
            <View style={styles.stepProgressTrack}>
              <View
                style={[
                  styles.stepProgressFill,
                  {
                    width: `${(workflowState.stepsCompleted.filter(Boolean).length / workflow.steps.length) * 100}%`,
                  },
                ]}
              />
            </View>
          </View>
        </View>
      )}
    </GlassCard>
  );
}

// ─── Main Screen ────────────────────────────────────────────────
export default function RemoverScreen() {
  const {
    workflows,
    workflowStates,
    logEntries,
    verification,
    selectedCount,
    overallProgress,
    allRemediationComplete,
    remediationStarted,
    toggleSelectAll,
    toggleSelectWorkflow,
    toggleExpandWorkflow,
    markStepComplete,
    startRemediation,
    toggleVerificationItem,
    runVerificationCheck,
    getWorkflowState,
    getStepColor,
  } = useRemediation();

  const stats = getRemediationStats();
  const allSelected = workflowStates.every((ws) => ws.selected);
  const criticalCount = workflows.filter((w) => w.severity === 'critical').length;
  const warningCount = workflows.filter((w) => w.severity === 'high' || w.severity === 'medium').length;

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Remediate Threats</Text>
        <Text style={styles.headerSubtitle}>
          Select threats to remediate and follow guided removal steps.
        </Text>

        {/* Stat Pills */}
        <View style={styles.statRow}>
          <StatPill label="Critical" count={criticalCount} color={colors.accentDanger} />
          <StatPill label="Warnings" count={warningCount} color={colors.accentWarning} />
          <View style={styles.totalPill}>
            <Text style={styles.totalText}>Total: {workflows.length}</Text>
          </View>
        </View>

        {/* Select All */}
        <TouchableOpacity onPress={toggleSelectAll} style={styles.selectAllRow}>
          <View style={[styles.checkbox, allSelected && { backgroundColor: colors.accentMint, borderColor: colors.accentMint }]}>
            {allSelected && <Ionicons name="checkmark" size={14} color={colors.bgDeep} />}
          </View>
          <Text style={styles.selectAllText}>Select all threats for remediation</Text>
        </TouchableOpacity>
      </View>

      {/* Overall Progress */}
      {remediationStarted && (
        <View style={styles.overallProgress}>
          <View style={styles.overallProgressHeader}>
            <Text style={styles.overallProgressLabel}>Overall Progress</Text>
            <Text style={styles.overallProgressPercent}>{overallProgress}%</Text>
          </View>
          <View style={styles.overallProgressTrack}>
            <View
              style={[
                styles.overallProgressFill,
                {
                  width: `${overallProgress}%`,
                  backgroundColor: allRemediationComplete ? colors.accentSuccess : colors.accentMint,
                },
              ]}
            />
          </View>
        </View>
      )}

      {/* Workflow Cards */}
      <View style={styles.cardsContainer}>
        {workflows.map((workflow) => {
          const ws = getWorkflowState(workflow.id);
          if (!ws) return null;
          return (
            <WorkflowCard
              key={workflow.id}
              workflow={workflow}
              workflowState={ws}
              onToggleSelect={toggleSelectWorkflow}
              onToggleExpand={toggleExpandWorkflow}
              onMarkStepComplete={markStepComplete}
              getStepColor={getStepColor}
            />
          );
        })}
      </View>

      {/* Start Remediation Button */}
      {!remediationStarted ? (
        <View style={styles.ctaContainer}>
          <TouchableOpacity
            onPress={startRemediation}
            disabled={selectedCount === 0}
            style={[
              styles.ctaButton,
              selectedCount === 0 && styles.ctaButtonDisabled,
            ]}
            activeOpacity={0.85}
          >
            <Ionicons name="play" size={16} color={selectedCount > 0 ? colors.bgDeep : colors.textMuted} />
            <Text style={[styles.ctaText, selectedCount === 0 && styles.ctaTextDisabled]}>
              Start Remediation ({selectedCount} selected)
            </Text>
          </TouchableOpacity>
          <View style={styles.estTimeRow}>
            <Ionicons name="time" size={12} color={colors.textMuted} />
            <Text style={styles.estTimeText}>Est. {stats.estimatedMinutes} minutes</Text>
          </View>
        </View>
      ) : (
        <View style={styles.statusRow}>
          <View style={[styles.statusDot, { backgroundColor: allRemediationComplete ? colors.accentSuccess : colors.accentMint }]} />
          <Text style={styles.statusText}>
            {allRemediationComplete ? 'All remediation workflows complete' : 'Remediation in progress...'}
          </Text>
        </View>
      )}

      {/* Verification Checklist */}
      {remediationStarted && (
        <View style={styles.verificationSection}>
          <Text style={styles.sectionLabel}>POST-CLEANUP VERIFICATION</Text>
          <GlassCard>
            {verification.map((item) => (
              <TouchableOpacity
                key={item.id}
                onPress={() => toggleVerificationItem(item.id)}
                style={styles.verifyRow}
              >
                <View
                  style={[
                    styles.verifyCheckbox,
                    item.checked && { backgroundColor: colors.accentSuccess, borderColor: colors.accentSuccess },
                  ]}
                >
                  {item.checked && <Ionicons name="checkmark" size={12} color={colors.bgDeep} />}
                </View>
                <View style={styles.verifyContent}>
                  <Text style={[styles.verifyLabel, item.checked && styles.verifyLabelDone]}>
                    {item.label}
                  </Text>
                  <Text style={styles.verifyDesc}>{item.description}</Text>
                </View>
                {item.passed && (
                  <Ionicons name="checkmark-circle" size={16} color={colors.accentSuccess} />
                )}
              </TouchableOpacity>
            ))}

            <TouchableOpacity onPress={runVerificationCheck} style={styles.verifyRunButton}>
              <Ionicons name="refresh" size={14} color={colors.bgDeep} />
              <Text style={styles.verifyRunText}>Run Auto-Verification</Text>
            </TouchableOpacity>
          </GlassCard>
        </View>
      )}

      {/* Action Log */}
      {remediationStarted && logEntries.length > 0 && (
        <View style={styles.logSection}>
          <Text style={styles.sectionLabel}>ACTION LOG</Text>
          <GlassCard>
            {logEntries.slice(0, 10).map((entry) => (
              <View key={entry.id} style={styles.logRow}>
                <Ionicons
                  name={
                    entry.status === 'success'
                      ? 'checkmark-circle'
                      : entry.status === 'failed'
                      ? 'close-circle'
                      : 'time'
                  }
                  size={14}
                  color={
                    entry.status === 'success'
                      ? colors.accentSuccess
                      : entry.status === 'failed'
                      ? colors.accentDanger
                      : colors.accentWarning
                  }
                />
                <View style={styles.logContent}>
                  <Text style={styles.logAction}>{entry.action}: {entry.target}</Text>
                  {entry.details && <Text style={styles.logDetails}>{entry.details}</Text>}
                </View>
                <Text style={styles.logTime}>
                  {new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </Text>
              </View>
            ))}
          </GlassCard>
        </View>
      )}

      <View style={{ height: 40 }} />
    </ScrollView>
  );
}

// ─── Styles ─────────────────────────────────────────────────────
const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgDeep },
  content: { paddingHorizontal: spacing.lg, paddingTop: 40, paddingBottom: 40 },

  header: { alignItems: 'center', marginBottom: 20 },
  headerTitle: { fontSize: 28, fontWeight: '700', color: colors.textPrimary, marginBottom: 10, letterSpacing: -0.5 },
  headerSubtitle: { fontSize: 15, color: colors.textSecondary, textAlign: 'center', lineHeight: 22, maxWidth: 400, marginBottom: 16 },

  statRow: { flexDirection: 'row', gap: 8, marginBottom: 16, flexWrap: 'wrap', justifyContent: 'center' },
  statPill: { flexDirection: 'row', alignItems: 'center', gap: 6, paddingHorizontal: 12, paddingVertical: 6, borderRadius: borderRadius.full, borderWidth: 1 },
  statDot: { width: 8, height: 8, borderRadius: 4 },
  statPillText: { fontFamily: 'monospace', fontSize: 12 },
  totalPill: { paddingHorizontal: 12, paddingVertical: 6, borderRadius: borderRadius.full, backgroundColor: colors.bgGlass, borderWidth: 1, borderColor: colors.glassBorder },
  totalText: { fontFamily: 'monospace', fontSize: 12, color: colors.textSecondary },

  selectAllRow: { flexDirection: 'row', alignItems: 'center', gap: 10, paddingVertical: 8 },
  selectAllText: { fontSize: 14, color: colors.textSecondary },

  checkbox: { width: 22, height: 22, borderRadius: 4, borderWidth: 2, borderColor: colors.textMuted, alignItems: 'center', justifyContent: 'center' },

  overallProgress: { marginBottom: 16, padding: 16, borderRadius: borderRadius.md, backgroundColor: colors.accentMint + '0F', borderWidth: 1, borderColor: colors.accentMint + '20' },
  overallProgressHeader: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 },
  overallProgressLabel: { fontSize: 13, fontWeight: '600', color: colors.accentMint },
  overallProgressPercent: { fontFamily: 'monospace', fontSize: 12, fontWeight: '600', color: colors.accentMint },
  overallProgressTrack: { height: 8, borderRadius: 4, backgroundColor: colors.ringTrack, overflow: 'hidden' },
  overallProgressFill: { height: '100%', borderRadius: 4 },

  cardsContainer: { gap: 12, marginBottom: 20 },
  workflowCard: { padding: 0 },
  workflowHeader: { flexDirection: 'row', alignItems: 'flex-start', padding: 14, gap: 12 },
  workflowInfo: { flex: 1, gap: 4 },
  workflowTitleRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  workflowTitle: { fontSize: 15, fontWeight: '600', color: colors.textPrimary, flex: 1, marginRight: 8 },
  workflowCategory: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted, textTransform: 'uppercase', letterSpacing: 1 },
  workflowDesc: { fontSize: 13, color: colors.textSecondary, lineHeight: 18 },

  stepsContainer: { paddingHorizontal: 14, paddingBottom: 14 },
  stepsDivider: { height: 1, backgroundColor: colors.glassBorder, marginBottom: 12 },
  stepsLabel: { fontFamily: 'monospace', fontSize: 9, color: colors.textMuted, letterSpacing: 1.5, marginBottom: 12 },

  stepRow: { flexDirection: 'row', alignItems: 'flex-start', marginBottom: 12, paddingLeft: 4 },
  stepRowActive: { backgroundColor: colors.accentMint + '08', borderRadius: 8, marginLeft: -4, paddingLeft: 8, paddingVertical: 4 },
  stepLeft: { flexDirection: 'row', alignItems: 'flex-start', gap: 10, flex: 1 },
  stepCheckbox: { width: 20, height: 20, borderRadius: 10, borderWidth: 2, borderColor: colors.textMuted, alignItems: 'center', justifyContent: 'center', marginTop: 2 },
  stepContent: { flex: 1, gap: 4 },
  stepTitleRow: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  stepNumber: { fontFamily: 'monospace', fontSize: 11, fontWeight: '700' },
  stepTitle: { fontSize: 13, fontWeight: '600', color: colors.textPrimary },
  stepTitleComplete: { textDecorationLine: 'line-through', color: colors.textMuted },
  stepDesc: { fontSize: 12, color: colors.textSecondary, lineHeight: 16 },
  stepTags: { flexDirection: 'row', gap: 6, marginTop: 2 },
  actionTag: { paddingHorizontal: 8, paddingVertical: 2, borderRadius: borderRadius.full },
  actionTagText: { fontFamily: 'monospace', fontSize: 9, fontWeight: '600', letterSpacing: 0.5 },

  stepProgress: { marginTop: 8, gap: 4 },
  stepProgressText: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted },
  stepProgressTrack: { height: 4, borderRadius: 2, backgroundColor: colors.ringTrack, overflow: 'hidden' },
  stepProgressFill: { height: '100%', borderRadius: 2, backgroundColor: colors.accentMint },

  ctaContainer: { alignItems: 'center', gap: 10, marginTop: 10 },
  ctaButton: { flexDirection: 'row', alignItems: 'center', gap: 8, backgroundColor: colors.accentMint, paddingVertical: 14, paddingHorizontal: 24, borderRadius: borderRadius.md },
  ctaButtonDisabled: { backgroundColor: colors.bgSurface },
  ctaText: { fontSize: 14, fontWeight: '600', color: colors.bgDeep },
  ctaTextDisabled: { color: colors.textMuted },
  estTimeRow: { flexDirection: 'row', alignItems: 'center', gap: 6 },
  estTimeText: { fontFamily: 'monospace', fontSize: 11, color: colors.textMuted },

  statusRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8, marginTop: 16 },
  statusDot: { width: 8, height: 8, borderRadius: 4 },
  statusText: { fontFamily: 'monospace', fontSize: 12, color: colors.textSecondary },

  verificationSection: { marginTop: 30, gap: 10 },
  sectionLabel: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted, letterSpacing: 1.5, marginBottom: 6 },
  verifyRow: { flexDirection: 'row', alignItems: 'flex-start', gap: 10, paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: colors.glassBorder },
  verifyCheckbox: { width: 18, height: 18, borderRadius: 4, borderWidth: 1.5, borderColor: colors.textMuted, alignItems: 'center', justifyContent: 'center', marginTop: 2 },
  verifyContent: { flex: 1, gap: 2 },
  verifyLabel: { fontSize: 13, fontWeight: '600', color: colors.textPrimary },
  verifyLabelDone: { textDecorationLine: 'line-through', color: colors.textMuted },
  verifyDesc: { fontSize: 11, color: colors.textSecondary },
  verifyRunButton: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 6, backgroundColor: colors.accentMint, paddingVertical: 10, borderRadius: borderRadius.md, marginTop: 12 },
  verifyRunText: { fontSize: 13, fontWeight: '600', color: colors.bgDeep },

  logSection: { marginTop: 24, gap: 10 },
  logRow: { flexDirection: 'row', alignItems: 'flex-start', gap: 10, paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: colors.glassBorder },
  logContent: { flex: 1, gap: 2 },
  logAction: { fontSize: 12, fontWeight: '600', color: colors.textPrimary },
  logDetails: { fontSize: 11, color: colors.textSecondary },
  logTime: { fontFamily: 'monospace', fontSize: 10, color: colors.textMuted },
});
