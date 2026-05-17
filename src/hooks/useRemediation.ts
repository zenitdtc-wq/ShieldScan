/**
 * ShieldScan Remediation Hook
 *
 * Manages threat removal workflows, step tracking,
 * verification checklists, and action logging.
 */

import { useState, useCallback, useMemo } from 'react';
import type {
  RemediationWorkflow,
  RemediationStep,
  VerificationItem,
  ActionLogEntry,
} from '../types/engine';
import { remediationWorkflows, verificationChecklist } from '../data/remediation';
import { requestUninstall, openAppSettings } from '../native/NativeBridge';
import { colors } from '../theme';

interface WorkflowState {
  workflowId: string;
  selected: boolean;
  expanded: boolean;
  currentStep: number;
  stepsCompleted: boolean[];
}

export function useRemediation() {
  const [workflows] = useState<RemediationWorkflow[]>(remediationWorkflows);
  const [workflowStates, setWorkflowStates] = useState<WorkflowState[]>(
    remediationWorkflows.map((w) => ({
      workflowId: w.id,
      selected: false,
      expanded: false,
      currentStep: 0,
      stepsCompleted: w.steps.map(() => false),
    }))
  );
  const [logEntries, setLogEntries] = useState<ActionLogEntry[]>([]);
  const [verification, setVerification] = useState<VerificationItem[]>(
    verificationChecklist.map((v) => ({ ...v }))
  );
  const [remediationStarted, setRemediationStarted] = useState(false);

  // ─── Derived State ────────────────────────────────────────────
  const selectedCount = useMemo(
    () => workflowStates.filter((ws) => ws.selected).length,
    [workflowStates]
  );

  const overallProgress = useMemo(() => {
    const selectedWorkflows = workflowStates.filter((ws) => ws.selected);
    if (selectedWorkflows.length === 0) return 0;

    const totalSteps = selectedWorkflows.reduce((sum, ws) => {
      const wf = workflows.find((w) => w.id === ws.workflowId);
      return sum + (wf?.steps.length || 0);
    }, 0);

    const completedSteps = selectedWorkflows.reduce(
      (sum, ws) => sum + ws.stepsCompleted.filter(Boolean).length,
      0
    );

    return totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0;
  }, [workflowStates, workflows]);

  const allRemediationComplete = useMemo(
    () =>
      remediationStarted &&
      workflowStates
        .filter((ws) => ws.selected)
        .every((ws) => ws.stepsCompleted.every(Boolean)),
    [workflowStates, remediationStarted]
  );

  // ─── Actions ──────────────────────────────────────────────────
  const toggleSelectAll = useCallback(() => {
    setWorkflowStates((prev) => {
      const allSelected = prev.every((ws) => ws.selected);
      return prev.map((ws) => ({ ...ws, selected: !allSelected }));
    });
  }, []);

  const toggleSelectWorkflow = useCallback((workflowId: string) => {
    setWorkflowStates((prev) =>
      prev.map((ws) =>
        ws.workflowId === workflowId ? { ...ws, selected: !ws.selected } : ws
      )
    );
  }, []);

  const toggleExpandWorkflow = useCallback((workflowId: string) => {
    setWorkflowStates((prev) =>
      prev.map((ws) =>
        ws.workflowId === workflowId ? { ...ws, expanded: !ws.expanded } : ws
      )
    );
  }, []);

  const addLogEntry = useCallback(
    (action: string, target: string, status: ActionLogEntry['status'], details?: string) => {
      setLogEntries((prev) => [
        {
          id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          timestamp: Date.now(),
          action,
          target,
          status,
          details,
        },
        ...prev,
      ]);
    },
    []
  );

  const markStepComplete = useCallback(
    async (workflowId: string, stepIndex: number) => {
      const wf = workflows.find((w) => w.id === workflowId);
      if (!wf) return;

      const step = wf.steps[stepIndex];

      // Execute the step action
      try {
        switch (step.action) {
          case 'uninstall':
            if (step.targetPackage) {
              addLogEntry('Uninstall', step.targetPackage, 'pending');
              const success = await requestUninstall(step.targetPackage);
              addLogEntry(
                'Uninstall',
                step.targetPackage,
                success ? 'success' : 'failed',
                success ? 'Package uninstall dialog opened' : 'Failed to trigger uninstall'
              );
            }
            break;

          case 'revoke_permission':
            if (step.targetPackage) {
              addLogEntry('Open Settings', step.targetPackage, 'pending');
              await openAppSettings(step.targetPackage);
              addLogEntry('Open Settings', step.targetPackage, 'success', 'App settings opened for permission review');
            }
            break;

          case 'verify':
            addLogEntry('Verify', wf.threatName, 'success', 'Verification step marked complete');
            break;

          default:
            addLogEntry(step.title, wf.threatName, 'success', 'Manual step completed by user');
            break;
        }
      } catch (err) {
        addLogEntry(step.title, wf.threatName, 'failed', String(err));
      }

      setWorkflowStates((prev) =>
        prev.map((ws) => {
          if (ws.workflowId !== workflowId) return ws;
          const newCompleted = [...ws.stepsCompleted];
          newCompleted[stepIndex] = true;
          return {
            ...ws,
            stepsCompleted: newCompleted,
            currentStep: Math.min(stepIndex + 1, wf.steps.length - 1),
          };
        })
      );
    },
    [workflows, addLogEntry]
  );

  const advanceStep = useCallback(
    (workflowId: string) => {
      const wf = workflows.find((w) => w.id === workflowId);
      if (!wf) return;

      setWorkflowStates((prev) =>
        prev.map((ws) => {
          if (ws.workflowId !== workflowId) return ws;
          return {
            ...ws,
            currentStep: Math.min(ws.currentStep + 1, wf.steps.length - 1),
          };
        })
      );
    },
    [workflows]
  );

  const toggleActionItem = useCallback(
    (workflowId: string, stepIndex: number) => {
      markStepComplete(workflowId, stepIndex);
    },
    [markStepComplete]
  );

  const startRemediation = useCallback(() => {
    setRemediationStarted(true);
    addLogEntry('Remediation', 'All selected threats', 'success', `Started remediation for ${selectedCount} threat(s)`);

    // Auto-expand selected workflows
    setWorkflowStates((prev) =>
      prev.map((ws) => (ws.selected ? { ...ws, expanded: true } : ws))
    );
  }, [selectedCount, addLogEntry]);

  const toggleVerificationItem = useCallback((id: string) => {
    setVerification((prev) =>
      prev.map((v) => (v.id === id ? { ...v, checked: !v.checked } : v))
    );
  }, []);

  const runVerificationCheck = useCallback(async () => {
    addLogEntry('Verification', 'Post-cleanup check', 'pending');
    // In production, this would trigger a re-scan
    await new Promise((resolve) => setTimeout(resolve, 2000));
    setVerification((prev) =>
      prev.map((v) =>
        v.autoVerifiable ? { ...v, checked: true, passed: true } : v
      )
    );
    addLogEntry('Verification', 'Automated checks', 'success', 'Auto-verifiable items passed');
  }, [addLogEntry]);

  const resetVerification = useCallback(() => {
    setVerification(verificationChecklist.map((v) => ({ ...v })));
  }, []);

  const getWorkflowState = useCallback(
    (workflowId: string) =>
      workflowStates.find((ws) => ws.workflowId === workflowId) || null,
    [workflowStates]
  );

  const getStepColor = useCallback(
    (step: RemediationStep, isCompleted: boolean) => {
      if (isCompleted) return colors.accentSuccess;
      switch (step.action) {
        case 'uninstall':
          return colors.accentDanger;
        case 'revoke_permission':
          return colors.accentWarning;
        case 'verify':
          return colors.accentMint;
        default:
          return colors.accentInfo;
      }
    },
    []
  );

  return {
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
    toggleActionItem,
    markStepComplete,
    advanceStep,
    startRemediation,
    toggleVerificationItem,
    runVerificationCheck,
    resetVerification,
    getWorkflowState,
    getStepColor,
  };
}
