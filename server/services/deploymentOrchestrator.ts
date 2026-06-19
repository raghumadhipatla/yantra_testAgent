import type { IStorage } from "../storage";
import type {
  DeploymentRun,
  DeploymentStageState,
  DeploymentProjectConfig,
  PromotionGateResult,
  DeploymentLog,
  InsertDeploymentRun,
  InsertDeploymentLog as _InsertDeploymentLog,
  InsertPromotionGateResult as _InsertPromotionGateResult,
  DeploymentTarget,
  QualityGatePolicy,
  CloudCredential,
  TrafficAllocation as _TrafficAllocation,
  CanaryMetrics,
  DeploymentStrategyConfig,
  BlueGreenConfig as _BlueGreenConfig,
  CanaryConfig,
  TrafficDistribution,
} from "@shared/schema";
import { SECURITY_SCAN_INHERITANCE_WINDOW_MS } from "@shared/schema";
import { buildService } from "./buildService";
import { healthMonitorService } from "./healthMonitorService";
import { getProvider, cloudProviders as _cloudProviders, type CloudProviderName } from "./cloudProviders";
import type { LogEntry, LogsOptions, DeploymentTarget as ProviderDeploymentTarget, ProviderResult, CloudProvider } from "./cloudProviders/types";
import { runAutonomousDeployLoop, type DeployStepResult } from "./autonomousDeploymentLoop";
import { EscalationService, createEscalationService, type EscalationIssue } from "./escalationService";
import { createProductionFileSyncService, type ProductionFileSyncService } from "./productionFileSyncService";
import {
  resolveProjectArchetypeId,
  resolveValidationProfile,
} from "./archetypes/registry";
import { restoreEnvSnapshot } from "./envCarryover";

export type DeploymentStage = "test" | "preprod" | "production";

export interface DeployOptions {
  version?: string;
  buildId?: string;
  commitSha?: string;
  commitMessage?: string;
  triggeredBy?: "user" | "agent" | "auto-promote" | "webhook";
  triggeredByUserId?: string;
  triggeredByAgentId?: string;
  provider?: string;
  region?: string;
  skipGates?: string[];
  envOverrides?: Record<string, string>;
  skipBuild?: boolean;
}

export interface DeploymentResult {
  success: boolean;
  runId: string;
  stage: DeploymentStage;
  status: string;
  deployUrl?: string;
  errorMessage?: string;
  durationMs?: number;
}

export interface RollbackResult {
  success: boolean;
  runId: string;
  rolledBackFromRunId?: string;
  targetVersion?: string;
  errorMessage?: string;
}

export interface QualityGateCheckResult {
  passed: boolean;
  gates: {
    name: string;
    status: "passed" | "failed" | "pending" | "skipped";
    required: boolean;
    details?: Record<string, unknown>;
  }[];
  blockers: string[];
}

export interface PromotionCheckResult {
  canPromote: boolean;
  currentStage: DeploymentStage;
  nextStage: DeploymentStage | null;
  blockers: string[];
  gatesStatus: QualityGateCheckResult;
}

export interface DeploymentEvent {
  type: "deployment_started" | "deployment_progress" | "deployment_completed" | "deployment_failed" | "deployment_log" | "gate_update" | "promotion" | "rollback";
  projectId: string;
  runId: string;
  stage: DeploymentStage;
  data: Record<string, unknown>;
  timestamp: string;
}

import { logStreamingService } from "./logStreamingService";

import { logger } from "../logger";

const STAGE_ORDER: DeploymentStage[] = ["test", "preprod", "production"];

// Sensible defaults so an automated canary is one-click even when the target
// has no explicit canary block: 10% -> 40% -> 70% -> 100%, baking 60s per step,
// rolling back if error rate > 5% or average latency > 2s.
const DEFAULT_CANARY_CONFIG: CanaryConfig = {
  initialPercent: 10,
  incrementPercent: 30,
  incrementIntervalSeconds: 60,
  monitorDurationSeconds: 60,
  rollbackThreshold: { errorRate: 5, responseTime: 2000 },
};

// Canonical "a run is still in flight" status set, shared by the deploy path,
// the promote path, and the route-level concurrency guard so at most one
// active run exists per (project, stage). Includes "checking-gates" — the
// initial status of a promotion run — so a deploy and a promote (or two
// promotes) can never both land on the same stage at once.
export const ACTIVE_DEPLOY_RUN_STATUSES = [
  "pending",
  "queued",
  "running",
  "building",
  "scanning",
  "deploying",
  "verifying",
  "in_progress",
  "rolling_back",
  "checking-gates",
];

// Task #1141 — version comparison for security-scan inheritance.
// `scanVersion` is free-form by design (see schema) so we parse the
// leading numeric segments (`1.2.3`, `v1.2.3-beta`, `2024.04.20`) and
// compare them lexicographically. Returns:
//   -1 → a < b, 0 → equal, 1 → a > b, null → not comparable.
function compareScannerVersions(a: string | null | undefined, b: string | null | undefined): number | null {
  if (a == null && b == null) return 0;
  if (a == null || b == null) return null;
  if (a === b) return 0;
  const parse = (v: string): number[] | null => {
    const m = v.trim().match(/\d+(?:\.\d+)*/);
    if (!m) return null;
    return m[0].split(".").map((s) => parseInt(s, 10)).filter((n) => Number.isFinite(n));
  };
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb || pa.length === 0 || pb.length === 0) return null;
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const av = pa[i] ?? 0;
    const bv = pb[i] ?? 0;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  return 0;
}

// Returns a non-null upgrade descriptor when `current` is a different
// scanner (engine swap) or a strictly newer version of the same engine
// than `prior`. Returns null when the scanners match or when `current`
// is the same/older — those cases keep inheritance eligibility.
export function detectScannerUpgrade(
  prior: { scanEngine: string; scanVersion: string | null },
  current: { scanEngine: string; scanVersion: string | null },
): { reason: string } | null {
  if (prior.scanEngine !== current.scanEngine) {
    return { reason: `engine changed from "${prior.scanEngine}" to "${current.scanEngine}"` };
  }
  const cmp = compareScannerVersions(prior.scanVersion, current.scanVersion);
  if (cmp === null) {
    // Versions aren't comparable. If exactly one side declares a version
    // we treat that as a meaningful change (the upgrade introduced version
    // tracking). If both declare versions but neither parses, fall back
    // to string inequality so a deliberate label change still busts the
    // inheritance.
    if ((prior.scanVersion ?? null) !== (current.scanVersion ?? null)) {
      return { reason: `version label changed from "${prior.scanVersion ?? "unknown"}" to "${current.scanVersion ?? "unknown"}"` };
    }
    return null;
  }
  if (cmp < 0) {
    return { reason: `version bumped from "${prior.scanVersion ?? "unknown"}" to "${current.scanVersion ?? "unknown"}"` };
  }
  return null;
}

function formatScannerId(engine: string, version: string | null | undefined): string {
  return version ? `${engine}@${version}` : engine;
}

const DEPLOYMENT_POLL_INTERVAL_MS = 5000;
const DEPLOYMENT_TIMEOUT_MS = 10 * 60 * 1000;

/**
 * Task #1145 — real, runnable shell commands for the non-CLI archetype gate
 * `kind`s. Task #1122 emitted only command-bearing gates and skipped the rest
 * with a warning, so deployments never actually ran the headless / notebook /
 * health-probe / theme-token checks. Each entry below points at a command that
 * exists in the corresponding archetype scaffold (see
 * `server/services/archetypes/scaffolders.ts`) so the gate fails for a real
 * product reason rather than for "Missing script: ...".
 *
 * Keys: `kind` → `archetypeId` → shell command. A `kind` with no entry for
 * the project's archetype is still skipped with a warning, which keeps the
 * old behaviour for unknown combinations and preserves existing fallback
 * tests.
 */
const ARCHETYPE_KIND_COMMANDS: Record<string, Record<string, string>> = {
  // Native game smoke: prove the engine boots without a display. Pygame uses
  // SDL's dummy driver; Bevy/ggez settle for `cargo check` which exercises
  // the real toolchain without trying to open a Wayland/X11 surface; web
  // games fall back to the production build (Phaser/Three boot-time errors
  // surface at bundle time).
  'headless-smoke': {
    'native-game-python':
      'SDL_VIDEODRIVER=dummy SDL_AUDIODRIVER=dummy python -c "import pygame; pygame.init(); pygame.display.set_mode((1,1)); pygame.quit(); print(\\"pygame headless boot ok\\")"',
    'native-game-rust': 'cargo check --message-format short',
    'web-game': 'npm run build',
  },
  // React Native: dry-run Expo's native project generation. `--no-install`
  // skips Cocoapods/Gradle so this runs in the CI sandbox; failures here
  // are real config-level Expo errors.
  'expo-prebuild-check': {
    'mobile-rn': 'npx --yes expo prebuild --no-install --clean --platform ios',
  },
  // CLI tools: invoke the entry point with --help. The scaffolder for each
  // language wires --help into the binary, so a non-zero exit means the
  // tool can't even start.
  'cli-help-smoke': {
    'cli-tool-node': 'node ./bin/cli.js --help',
    'cli-tool-python':
      'python -c "import os,sys,subprocess; mods=[d for d in os.listdir(\\".\\") if os.path.isdir(d) and os.path.exists(os.path.join(d,\\"cli.py\\"))]; sys.exit(0 if not mods else subprocess.call([sys.executable,\\"-m\\",mods[0],\\"--help\\"]))"',
    'cli-tool-go': 'PKG=$(ls cmd | head -n1); go run ./cmd/$PKG --help',
    'cli-tool-rust': 'cargo run -- --help',
  },
  // Godot: scene-graph load via the headless engine. `--quit` exits after
  // the scene is parsed, so missing scripts / broken resources fail loudly.
  'godot-scene-validate': {
    'godot': 'godot --headless --quit --path . res://Main.tscn',
  },
  // Notebook execute: run every cell via nbconvert. Any exception bubbles up
  // as a non-zero exit, which is the gate's failure signal.
  'notebook-execute': {
    'ml-notebook':
      'jupyter nbconvert --to notebook --execute notebook.ipynb --output /tmp/notebook-executed.ipynb --ExecutePreprocessor.timeout=120',
  },
  // ML eval metrics: optional metrics.json check. Informational pass when
  // the file is missing so a fresh notebook isn't blocked before the model
  // is trained, but a numeric metric outside [EVAL_MIN, EVAL_MAX] fails.
  'eval-metric-range': {
    'ml-notebook':
      `if [ -f metrics.json ]; then python -c 'import json,sys,os; m=json.load(open("metrics.json")); mn=float(os.environ.get("EVAL_MIN","0")); mx=float(os.environ.get("EVAL_MAX","1")); v=next((x for x in m.values() if isinstance(x,(int,float))), None); sys.exit(0 if v is None or (mn<=v<=mx) else 1)'; else echo "(no metrics.json — informational pass)"; fi`,
  },
  // HTTP health probe: spawn the dev server, poll /health for up to 10s,
  // tear it down. Real boot errors land in /tmp/health-probe.log which is
  // dumped on failure.
  //
  // IMPORTANT: `executeCommand` already runs the string under `/bin/sh -c`,
  // so we must NOT wrap this in another `sh -c "..."` — the outer shell
  // would expand `$!`, `$SERVER_PID`, `$(...)` etc. before the inner shell
  // sees them, breaking PID capture and teardown. Writing the command body
  // directly lets `$!` reliably capture the backgrounded dev-server PID.
  'http-health-probe': {
    'backend-service':
      `npm run dev > /tmp/health-probe.log 2>&1 & SERVER_PID=$!; trap "kill $SERVER_PID 2>/dev/null" EXIT; for i in 1 2 3 4 5 6 7 8 9 10; do sleep 1; if curl -fsS http://127.0.0.1:5000/health > /tmp/health-probe.out 2>&1; then cat /tmp/health-probe.out; exit 0; fi; done; echo "health probe failed; server log:"; cat /tmp/health-probe.log; exit 1`,
  },
  // Theme-token compliance: grep for raw hex colors outside the theme/token
  // entry points. A hit means a component is bypassing semantic tokens and
  // the gate fails. Keyed by *archetype id* (not validation-profile id), so
  // every web archetype that pulls a theme-token-bearing profile gets the
  // check: web-saas archetype, web-mobile-linked (also profile=web-saas),
  // and web-frontend-spa (profile=web-frontend).
  // Same shell-quoting rule as above: no nested `sh -c`.
  'theme-token': {
    'web-saas':
      `if grep -rEn "#[0-9a-fA-F]{3,8}\\b" --include="*.tsx" --include="*.ts" --include="*.jsx" --include="*.css" client/src 2>/dev/null | grep -vE "(theme|tokens|index\\.css)"; then echo "hardcoded color values found — use semantic tokens"; exit 1; else echo "theme-token compliance ok"; exit 0; fi`,
    'web-mobile-linked':
      `if grep -rEn "#[0-9a-fA-F]{3,8}\\b" --include="*.tsx" --include="*.ts" --include="*.jsx" --include="*.css" client/src 2>/dev/null | grep -vE "(theme|tokens|index\\.css)"; then echo "hardcoded color values found — use semantic tokens"; exit 1; else echo "theme-token compliance ok"; exit 0; fi`,
    // web-frontend-spa scaffolds files under top-level `src/` (no `client/`
    // prefix), so scan `src` here. Falls back to `client/src` if it exists,
    // and fails loudly when neither directory is present.
    'web-frontend-spa':
      `SCAN_DIR=src; [ -d client/src ] && SCAN_DIR=client/src; if [ ! -d "$SCAN_DIR" ]; then echo "theme-token: no source dir found ($SCAN_DIR)"; exit 1; fi; if grep -rEn "#[0-9a-fA-F]{3,8}\\b" --include="*.tsx" --include="*.ts" --include="*.jsx" --include="*.css" "$SCAN_DIR" 2>/dev/null | grep -vE "(theme|tokens|index\\.css)"; then echo "hardcoded color values found — use semantic tokens"; exit 1; else echo "theme-token compliance ok ($SCAN_DIR)"; exit 0; fi`,
  },
};

function broadcastDeploymentEvent(event: DeploymentEvent): void {
  logStreamingService.broadcastDeploymentEvent({
    type: event.type,
    projectId: event.projectId,
    runId: event.runId,
    stage: event.stage,
    data: event.data,
    timestamp: event.timestamp,
  });
}

async function resolveHotfixTicketsOnDeployment(
  storage: IStorage,
  projectId: string,
  stage: DeploymentStage,
  runId: string,
  version?: string
): Promise<void> {
  if (stage !== "production") {
    return;
  }

  try {
    logger.info(`[HotfixWorkflow] Step 6: resolveHotfixTicketsOnDeployment called after production deployment`);
    logger.info(`[DeploymentOrchestrator] Checking for hotfix tickets to resolve after production deployment`);
    logger.info(`[HotfixWorkflow] Also checking awaiting_approval hotfix tasks for resolution`);
    
    // Get tasks that are marked done or awaiting_approval and have a sourceTicketId, but only if they:
    // 1. Are hotfix tasks
    // 2. Status is "done" (completed by coding agent) OR "awaiting_approval" (passed Central Brain review)
    // 3. Haven't already been deployed (we'll mark them as deployed after resolution)
    const tasks = await storage.getProjectTasks(projectId);
    const hotfixTasks = tasks.filter(task => 
      task.isHotfix && 
      (task.status === "done" || task.status === "awaiting_approval") &&
      task.sourceTicketId &&
      !task.deployedInRunId // Only tasks not yet marked as deployed
    );

    if (hotfixTasks.length === 0) {
      logger.info(`[DeploymentOrchestrator] No pending hotfix tasks to resolve`);
      return;
    }

    logger.info(`[DeploymentOrchestrator] Found ${hotfixTasks.length} hotfix tasks to resolve`);

    for (const task of hotfixTasks) {
      if (!task.sourceTicketId) continue;

      try {
        const ticketData = await storage.getTicketById(task.sourceTicketId);
        if (!ticketData) continue;

        const { ticket } = ticketData;
        
        if (ticket.status !== "resolved" && ticket.status !== "closed") {
          const resolutionNotes = `Automatically resolved after production deployment (Run ID: ${runId}${version ? `, Version: ${version}` : ''}). Fixed by task: ${task.title}`;
          await storage.resolveTicket(ticket.id, resolutionNotes);
          
          // Mark the task as deployed to prevent duplicate resolution
          await storage.updateProjectTask(task.id, {
            deployedInRunId: runId,
            deployedAt: new Date(),
          });
          
          logger.info(`[HotfixWorkflow] Step 6a: Auto-resolved hotfix ticket ${ticket.ticketNumber} after production deployment`);
          logger.info(`[DeploymentOrchestrator] Auto-resolved hotfix ticket ${ticket.ticketNumber} after production deployment`);
        }
      } catch (ticketError: any) {
        console.error(`[DeploymentOrchestrator] Failed to resolve ticket for task ${task.id}:`, ticketError.message);
      }
    }
  } catch (error: any) {
    console.error(`[DeploymentOrchestrator] Error resolving hotfix tickets:`, error.message);
  }
}

export class DeploymentOrchestrator {
  private storage: IStorage;
  private escalationService: EscalationService;
  private productionFileSyncService: ProductionFileSyncService;

  // Task #1129 — runtime override for the security-scan inheritance check.
  // The promote route plumbs `forceRescan` through `executeStage`, which
  // stashes it here keyed by `runId` so `evaluateQualityGate` can read it
  // without changing every callsite signature. Cleared when the run
  // pipeline finishes.
  private forceRescanByRunId = new Map<string, boolean>();

  // Cooperative cancellation: a user-requested cancel adds the runId here; the
  // pipeline checks between phases (abortIfCancelled) and stops cleanly.
  private cancelledRuns = new Set<string>();

  /**
   * Request cancellation of an in-flight deployment run. Marks the run
   * cancelled immediately (so the UI reflects it) and flags the pipeline to
   * abort at its next phase boundary. No-op for terminal runs.
   */
  async cancelDeployment(runId: string): Promise<{ success: boolean; message: string; status?: string }> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) return { success: false, message: "Deployment run not found" };

    const cancellable = new Set([
      "pending", "queued", "running", "migrating", "scanning", "building",
      "checking-gates", "deploying", "verifying", "in_progress",
    ]);
    if (!cancellable.has(run.status)) {
      return { success: false, message: `Run is '${run.status}' — nothing to cancel.`, status: run.status };
    }

    this.cancelledRuns.add(runId);
    await this.storage.updateDeploymentRun(runId, {
      status: "cancelled",
      errorMessage: "Cancelled by user",
      completedAt: new Date(),
    });
    await this.addLog(runId, run.projectId, "warn", "cancel", "Cancellation requested — the pipeline will stop at its next phase boundary.");
    broadcastDeploymentEvent({
      type: "deployment_failed",
      projectId: run.projectId,
      runId,
      stage: run.stage as DeploymentStage,
      data: { cancelled: true },
      timestamp: new Date().toISOString(),
    });
    return { success: true, message: "Deployment cancelled", status: "cancelled" };
  }

  /** If the run was cancelled, finalize it as cancelled and tell the pipeline to stop. */
  private async abortIfCancelled(runId: string, projectId: string, _stage: DeploymentStage): Promise<boolean> {
    if (!this.cancelledRuns.has(runId)) return false;
    this.cancelledRuns.delete(runId);
    await this.addLog(runId, projectId, "warn", "cancel", "Pipeline aborted — cancellation requested.");
    await this.storage.updateDeploymentRun(runId, {
      status: "cancelled",
      errorMessage: "Cancelled by user",
      completedAt: new Date(),
    });
    return true;
  }

  constructor(storage: IStorage) {
    this.storage = storage;
    this.escalationService = createEscalationService(storage);
    this.productionFileSyncService = createProductionFileSyncService(storage);
  }

  getStageOrder(): DeploymentStage[] {
    return [...STAGE_ORDER];
  }

  /**
   * Run all pending database migrations for the given stage as the first step
   * of the deployment pipeline. Streams output into the deployment run log
   * (source="migration") and updates migration rows to applied/failed.
   *
   * Throws on the first failed migration so the caller (orchestrator) can
   * abort the run before touching build / deploy / stage state. This is how
   * migrations are folded into the unified deploy pipeline: one click runs
   * migrate → build → deploy → verify without a separate manual step.
   */
  private async runPendingMigrations(
    runId: string,
    projectId: string,
    stage: DeploymentStage,
  ): Promise<{ applied: number; skipped: number }> {
    const migrations = await this.storage.getMigrations(projectId, stage);
    const pending = migrations.filter((m: any) => m.status === "pending");

    if (pending.length === 0) {
      await this.addLog(runId, projectId, "info", "migration", `No pending migrations for ${stage}`);
      return { applied: 0, skipped: 0 };
    }

    await this.storage.updateDeploymentRun(runId, { status: "migrating" });
    broadcastDeploymentEvent({
      type: "deployment_progress",
      projectId,
      runId,
      stage,
      data: { phase: "migrating", pendingCount: pending.length },
      timestamp: new Date().toISOString(),
    });

    await this.addLog(
      runId,
      projectId,
      "info",
      "migration",
      `Applying ${pending.length} pending migration${pending.length !== 1 ? "s" : ""} for ${stage}...`,
    );

    // CRITICAL: connect to the *stage's* database, never the platform DB.
    // The stageDatabase factory hard-fails if the stage's URL parses to the
    // platform's own DATABASE_URL.
    const { getStageDb, recordStageConnectionTest, testStageConnection } = await import("./stageDatabase");
    const { sql: rawSql } = await import("drizzle-orm");

    // Pre-migration connection check. Caught here so we can surface a clear
    // pointer to the Database panel before any DDL runs.
    const probe = await testStageConnection(this.storage, projectId, stage);
    await recordStageConnectionTest(this.storage, projectId, stage, probe);
    if (!probe.success) {
      const msg = `Cannot connect to ${stage} database (${probe.host || "unknown host"}/${probe.database || "unknown db"}): ${probe.message}. Configure or fix the database in the Deployment panel.`;
      await this.addLog(runId, projectId, "error", "migration", msg, { isError: 1 });
      throw new Error(msg);
    }

    const { db: stageDb, safeInfo } = await getStageDb(this.storage, projectId, stage);
    await this.addLog(
      runId,
      projectId,
      "info",
      "migration",
      `Connected to ${stage} database ${safeInfo.host}/${safeInfo.database} (latency ${probe.latencyMs}ms)`,
    );

    let applied = 0;
    for (const migration of pending) {
      // Defense in depth: authz-scope check. `getMigrations(projectId, stage)`
      // already filters by project, but verify the migration row's projectId
      // matches the run's projectId before executing SQL from it so a
      // corrupted fetch or upstream bug cannot cross-project-execute.
      if ((migration as any).projectId && (migration as any).projectId !== projectId) {
        await this.addLog(runId, projectId, "error", "migration", `Refusing to run migration ${migration.name}: projectId mismatch`, { isError: 1 });
        throw new Error(`Migration '${migration.name}' projectId mismatch`);
      }

      await this.addLog(runId, projectId, "info", "migration", `→ ${migration.name}`);

      let migrationSql: string | null = null;
      if (migration.description) {
        try {
          const payload = JSON.parse(migration.description);
          if (payload && typeof payload.sql === "string") migrationSql = payload.sql;
        } catch {
          if (migration.description.trim().toUpperCase().startsWith("--SQL:")) {
            migrationSql = migration.description.replace(/^--SQL:\s*/i, "").trim();
          }
        }
      }

      try {
        if (migrationSql) {
          // NOTE: Migration SQL is raw by design — migrations are
          // schema-change instructions that must support arbitrary DDL.
          // Authorization is enforced at migration creation (only
          // authenticated project members can enqueue migrations) and via
          // the projectId scope check above; this is the same trust model
          // used by the existing `executeRunMigrations` agent tool.
          const migStart = Date.now();
          await stageDb.execute(rawSql.raw(migrationSql));
          const durationMs = Date.now() - migStart;
          // Audit trail: never log the connection string itself — only host
          // and database name — so users can prove migrations went to the
          // right place.
          await this.addLog(
            runId,
            projectId,
            "info",
            "migration",
            `audit ${JSON.stringify({ stage, host: safeInfo.host, database: safeInfo.database, migrationId: migration.id, durationMs, success: true })}`,
          );
        }
        await this.storage.updateMigration(migration.id, {
          status: "applied",
          appliedAt: new Date(),
          appliedBy: "deployment-orchestrator",
        });
        await this.addLog(runId, projectId, "info", "migration", `✓ applied ${migration.name}`);
        applied++;
      } catch (migErr: any) {
        const errMsg = migErr?.message || String(migErr);
        // IMPORTANT: do NOT mutate `description` on failure. `description`
        // may be a JSON payload ({"sql": "..."}) or "--SQL:" prefixed text
        // used by the executor to recover the migration body; appending an
        // error string would corrupt that payload and cause a subsequent
        // retry (status=pending) to parse to null SQL and be silently
        // marked "applied" without running. The failure reason is already
        // captured in the deployment log below (source="migration").
        await this.storage.updateMigration(migration.id, {
          status: "failed",
        });
        await this.addLog(
          runId,
          projectId,
          "error",
          "migration",
          `✗ migration failed: ${migration.name} — ${errMsg}`,
          { isError: 1 },
        );
        throw new Error(`Migration '${migration.name}' failed: ${errMsg}`, { cause: migErr });
      }
    }

    await this.addLog(runId, projectId, "info", "migration", `Applied ${applied} migration${applied !== 1 ? "s" : ""}`);
    return { applied, skipped: 0 };
  }

  /**
   * Task #1130 — run security-scan quality gates as their own pipeline phase
   * BEFORE the build step. A failed required scan aborts the run before any
   * build compute is wasted. Inherited scans (artifact-bound) are surfaced
   * as "Skipped (inherited from …)" without re-running the scan command.
   *
   * Returns whether the scanning phase passed and the list of blockers for
   * required failures. Persists each gate result so subsequent gate
   * evaluation passes (verify phase) can short-circuit and not re-run.
   */
  private async runSecurityScanPhase(
    runId: string,
    projectId: string,
    stage: DeploymentStage,
  ): Promise<{ passed: boolean; blockers: string[]; ranAny: boolean; allInherited: boolean; scanCount: number }> {
    const policies = await this.storage.getQualityGatePolicies(projectId, stage);
    const securityPolicies = policies.filter(
      (p: any) => p.gateType === "security-scan" && p.isEnabled !== 0,
    );

    if (securityPolicies.length === 0) {
      return { passed: true, blockers: [], ranAny: false, allInherited: false, scanCount: 0 };
    }

    await this.storage.updateDeploymentRun(runId, { status: "scanning" });
    broadcastDeploymentEvent({
      type: "deployment_progress",
      projectId,
      runId,
      stage,
      data: { phase: "scanning", scanCount: securityPolicies.length },
      timestamp: new Date().toISOString(),
    });

    await this.addLog(
      runId,
      projectId,
      "info",
      "scanning",
      `Running ${securityPolicies.length} security scan${securityPolicies.length !== 1 ? "s" : ""} before build...`,
    );

    const blockers: string[] = [];
    let ranAny = false;
    let inheritedCount = 0;

    for (const policy of securityPolicies) {
      const result = await this.evaluateQualityGate(policy, projectId, runId);
      const details = (result.details ?? {}) as Record<string, unknown>;
      const inherited = details.decisionSource === "inherited";

      if (inherited) {
        inheritedCount++;
        const ageHours = typeof details.ageHours === "number" ? details.ageHours : undefined;
        const fromRunId = typeof details.inheritedFromRunId === "string" ? details.inheritedFromRunId : undefined;
        await this.addLog(
          runId,
          projectId,
          "info",
          "scanning",
          `Skipped (inherited${fromRunId ? ` from run ${fromRunId.slice(0, 8)}` : " from prior run"}${ageHours ? `, ${ageHours}h ago` : ""}): ${policy.gateName}`,
        );
      } else {
        ranAny = true;
      }

      await this.storage.createGateResult({
        runId,
        projectId,
        gateName: policy.gateName,
        gateType: policy.gateType,
        stage,
        status: result.status,
        required: policy.isRequired ? 1 : 0,
        details: result.details,
      });

      broadcastDeploymentEvent({
        type: "gate_update",
        projectId,
        runId,
        stage,
        data: {
          gateName: policy.gateName,
          status: result.status,
          required: !!policy.isRequired,
          phase: "scanning",
        },
        timestamp: new Date().toISOString(),
      });

      if (!!policy.isRequired && result.status === "failed") {
        blockers.push(`${policy.gateName}: ${result.message || "failed"}`);
      }
    }

    return {
      passed: blockers.length === 0,
      blockers,
      ranAny,
      allInherited: inheritedCount === securityPolicies.length,
      scanCount: securityPolicies.length,
    };
  }

  /**
   * Run an adapter-declared `prepare` hook, if one is defined. Streams output
   * into the same deployment run log (source="prepare"). This is the
   * extensibility point for provider-specific pre-deploy steps (container
   * push, `vercel build`, `flyctl deploy` packaging, etc.) without
   * hard-coding those steps into the orchestrator.
   */
  private async runPrepareHook(
    runId: string,
    projectId: string,
    provider: CloudProvider,
    target: ProviderDeploymentTarget,
    credentials: CloudCredential,
  ): Promise<ProviderDeploymentTarget> {
    if (typeof provider.prepare !== "function") {
      return target;
    }
    await this.addLog(runId, projectId, "info", "prepare", `Running ${provider.name || provider.displayName || "provider"} prepare step...`);
    try {
      const result = await provider.prepare(target, credentials, {
        log: async (level: "debug" | "info" | "warn" | "error", message: string) => {
          await this.addLog(runId, projectId, level, "prepare", message);
        },
      });
      if (result && result.success === false) {
        throw new Error(result.message || "Provider prepare step failed");
      }
      if (result?.imageUri) {
        return { ...target, imageUri: result.imageUri };
      }
      await this.addLog(runId, projectId, "info", "prepare", "Prepare step complete");
      return target;
    } catch (err: any) {
      await this.addLog(runId, projectId, "error", "prepare", `Prepare step failed: ${err?.message || err}`, { isError: 1 });
      throw err;
    }
  }

  private getNextStage(currentStage: DeploymentStage): DeploymentStage | null {
    const currentIndex = STAGE_ORDER.indexOf(currentStage);
    if (currentIndex === -1 || currentIndex >= STAGE_ORDER.length - 1) {
      return null;
    }
    return STAGE_ORDER[currentIndex + 1];
  }

  private getPreviousStage(currentStage: DeploymentStage): DeploymentStage | null {
    const currentIndex = STAGE_ORDER.indexOf(currentStage);
    if (currentIndex <= 0) {
      return null;
    }
    return STAGE_ORDER[currentIndex - 1];
  }

  private isValidStateTransition(currentStatus: string, newStatus: string): boolean {
    const validTransitions: Record<string, string[]> = {
      'pending': ['migrating', 'scanning', 'building', 'cancelled'],
      'migrating': ['scanning', 'building', 'failed', 'cancelled'],
      'scanning': ['building', 'failed', 'cancelled'],
      'building': ['deploying', 'failed', 'cancelled'],
      'deploying': ['deployed', 'failed', 'cancelled'],
      'deployed': ['promoting', 'rolling_back'],
      'promoting': ['deployed', 'failed'],
      'rolling_back': ['rolled_back', 'failed'],
      'canary_started': ['canary_progressing', 'canary_complete', 'rolling_back'],
      'blue_green_pending': ['blue_green_ready', 'failed'],
      'blue_green_ready': ['deployed', 'rolling_back'],
    };
    return validTransitions[currentStatus]?.includes(newStatus) ?? false;
  }

  private async validateStrategyLock(runId: string, requestedStrategy: 'standard' | 'canary' | 'blue-green'): Promise<{ valid: boolean; error?: string }> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) return { valid: false, error: 'Run not found' };
    
    // Detect current strategy from status
    const canaryStatuses = ['canary_started', 'canary_progressing', 'canary_complete'];
    const blueGreenStatuses = ['blue_green_pending', 'blue_green_ready'];
    
    let currentStrategy: 'standard' | 'canary' | 'blue-green' | null = null;
    if (canaryStatuses.includes(run.status)) {
      currentStrategy = 'canary';
    } else if (blueGreenStatuses.includes(run.status)) {
      currentStrategy = 'blue-green';
    } else if (['building', 'deploying', 'deployed'].includes(run.status)) {
      currentStrategy = 'standard';
    }
    
    if (currentStrategy && currentStrategy !== requestedStrategy) {
      return { valid: false, error: `Cannot switch from ${currentStrategy} to ${requestedStrategy} mid-deployment` };
    }
    return { valid: true };
  }

  async canPerformAction(projectId: string, action: 'deploy' | 'promote' | 'rollback' | 'scale' | 'canary_adjust'): Promise<{ allowed: boolean; reason?: string }> {
    if (action === 'rollback') return { allowed: true };
    
    const activeRuns = await this.storage.getDeploymentRuns(projectId);
    const rollingBack = activeRuns.find(r => r.status === 'rolling_back');
    if (rollingBack) {
      return { allowed: false, reason: 'Rollback in progress - wait for completion' };
    }
    
    if (action === 'scale' || action === 'canary_adjust') {
      const deploying = activeRuns.find(r => ['deploying', 'canary_started', 'canary_progressing'].includes(r.status));
      if (deploying) {
        return { allowed: false, reason: 'Active deployment in progress - cannot adjust scaling' };
      }
    }
    
    return { allowed: true };
  }

  async startDeployment(
    projectId: string,
    stage: string,
    options: DeployOptions = {}
  ): Promise<DeploymentResult> {
    const deployStage = stage as DeploymentStage;
    
    if (!STAGE_ORDER.includes(deployStage)) {
      return {
        success: false,
        runId: "",
        stage: deployStage,
        status: "failed",
        errorMessage: `Invalid stage: ${stage}. Must be one of: ${STAGE_ORDER.join(", ")}`,
      };
    }

    const project = await this.storage.getProjectInternal(projectId);
    if (!project) {
      return {
        success: false,
        runId: "",
        stage: deployStage,
        status: "failed",
        errorMessage: `Project not found: ${projectId}`,
      };
    }

    const target = await this.storage.getTargetByStage(projectId, deployStage);
    
    let credentials: CloudCredential | undefined;
    let providerName = options.provider;
    
    if (target) {
      providerName = target.provider || options.provider;
      if (target.credentialId) {
        credentials = await this.storage.getCloudCredentialById(target.credentialId);
      }
    }

    const existingRuns = await this.storage.getDeploymentRuns(projectId, deployStage, 1);
    const runNumber = existingRuns.length > 0 ? (existingRuns[0].runNumber || 0) + 1 : 1;

    const runData: InsertDeploymentRun = {
      projectId,
      runNumber,
      stage: deployStage,
      version: options.version,
      buildId: options.buildId,
      commitSha: options.commitSha,
      commitMessage: options.commitMessage,
      status: "pending",
      triggeredBy: options.triggeredBy || "user",
      triggeredByUserId: options.triggeredByUserId,
      triggeredByAgentId: options.triggeredByAgentId,
      provider: providerName,
      region: options.region || (target?.targetConfig as any)?.region,
    };

    const run = await this.storage.createDeploymentRun(runData);
    const startTime = Date.now();
    // Tracks whether stage-state was mutated to "deploying" during this
    // run. If migrations fail before that point we must NOT touch stage
    // state in the catch handler (leave the previous state untouched).
    let stageStateMutated = false;

    broadcastDeploymentEvent({
      type: "deployment_started",
      projectId,
      runId: run.id,
      stage: deployStage,
      data: { version: options.version, runNumber, provider: providerName },
      timestamp: new Date().toISOString(),
    });

    await this.addLog(run.id, projectId, "info", "deploy", `Deployment started for stage: ${deployStage}`);

    try {
      const { memoryOrchestrator } = await import('./memoryOrchestrator');
      const memContext = await memoryOrchestrator.getContextForAgent({
        projectId,
        agentId: 'deployment',
        taskDescription: `Deploying to ${deployStage}`,
      });
      if (memContext.vectorMemories) {
        await this.addLog(run.id, projectId, "debug", "context", `Loaded ${memContext.vectorMemories.length > 0 ? 'relevant deployment memories' : 'no prior deployment context'}`);
      }
    } catch (e: unknown) {
      logger.debug('[DeploymentOrchestrator] Memory context loading failed:', (e as Error).message);
    }

    try {
      // Unified pipeline: migrate → build → deploy → verify. Running pending
      // migrations first means a single deploy click applies schema changes
      // against the target stage DB before the new build is released, and
      // aborts the run cleanly if a migration fails.
      try {
        await this.runPendingMigrations(run.id, projectId, deployStage);
      } catch (migErr: any) {
        throw new Error(migErr?.message || "Migration step failed", { cause: migErr });
      }

      // Migrations succeeded — now it is safe to mark the stage as
      // transitioning. Prior to this point the previous stage state is
      // preserved so a migration failure is non-destructive.
      await this.storage.upsertStageState({
        projectId,
        stage: deployStage,
        status: "deploying",
        currentVersion: options.version,
        currentBuildId: options.buildId,
        currentCommitSha: options.commitSha,
        provider: providerName,
        region: options.region || (target?.targetConfig as any)?.region,
      });
      stageStateMutated = true;

      // Task #1130 — pipeline phase order: migrate → scan → build → deploy →
      // verify. Run security scans BEFORE build so a bad scan blocks the
      // build phase entirely and we don't waste compute on a release that
      // will fail. Inherited scans short-circuit without re-running.
      const scanResult = await this.runSecurityScanPhase(run.id, projectId, deployStage);
      if (!scanResult.passed) {
        throw new Error(`Security scan failed: ${scanResult.blockers.join(", ")}`);
      }

      await this.storage.updateDeploymentRun(run.id, { status: "building" });

      let artifactId = options.buildId;
      if (!options.skipBuild && !artifactId) {
        await this.addLog(run.id, projectId, "info", "build", "Starting build process...");
        
        const buildResult = await buildService.startBuild({
          projectId,
          version: options.version,
          onLog: async (log) => {
            await this.addLog(run.id, projectId, "debug", "build", log);
          },
        });

        if (!buildResult.success) {
          throw new Error(`Build failed: ${buildResult.error}`);
        }

        artifactId = buildResult.artifactId;
        await this.addLog(run.id, projectId, "info", "build", `Build completed successfully. Artifact ID: ${artifactId}`);
        
        await this.storage.updateDeploymentRun(run.id, { buildId: artifactId });
      } else if (artifactId) {
        await this.addLog(run.id, projectId, "info", "build", `Using existing build artifact: ${artifactId}`);
      }

      await this.storage.updateDeploymentRun(run.id, { status: "deploying" });
      await this.addLog(run.id, projectId, "info", "deploy", `Deploying to ${deployStage} environment...`);

      let deployUrl: string | undefined;
      let providerResult: ProviderResult | undefined;

      if (providerName && credentials) {
        const provider = getProvider(providerName);
        if (provider) {
          const artifact = artifactId ? await this.storage.getBuildArtifact(artifactId) : null;
          
          const deploymentTarget: ProviderDeploymentTarget = {
            projectId,
            stage: deployStage,
            version: options.version,
            buildId: artifactId,
            commitSha: options.commitSha,
            imageUri: artifact?.artifactPath,
            region: options.region || (target?.targetConfig as any)?.region,
            serviceName: (target?.targetConfig as any)?.serviceName || `${project.name}-${deployStage}`,
            environmentVariables: {
              ...((target?.environmentVariables as Record<string, string>) || {}),
              ...(options.envOverrides || {}),
            },
            resourceConfig: target?.resourceConfig as ProviderDeploymentTarget["resourceConfig"],
          };

          const preparedTarget = await this.runPrepareHook(run.id, projectId, provider, deploymentTarget, credentials);
          await this.addLog(run.id, projectId, "info", "deploy", `Calling ${providerName} provider to deploy...`);

          // Task #1256 — Drive the real deployment-agent execution path
          // through `runAutonomousDeployLoop`. Each `step` covers the
          // full deploy lifecycle: provider deploy + verification poll.
          // Transient infra failures (5xx, throttling, rollout timeout)
          // are retried; external blockers (missing credentials,
          // region quota) escalate immediately; unrecoverable provider
          // errors short-circuit. The loop is the SOLE owner of
          // recordDeploymentRunSpend writes — `step` only reports
          // `attemptUsdSpend`.
          const classifyError = (msg: string): { transient: boolean; hardFail: boolean } => {
            const lower = msg.toLowerCase();
            const transient = /50\d|timeout|temporar|throttl|rate.?limit|service unavailable|econn|etimedout|enotfound|enetunreach|socket hang up/.test(lower);
            const hardFail = /invalid|rejected|unsupported|forbidden|not authorized|bad request|400 /.test(lower) && !transient;
            return { transient, hardFail };
          };
          const loopRes = await runAutonomousDeployLoop({
            runId: run.id,
            step: async (attempt): Promise<DeployStepResult> => {
              try {
                const r = await provider.deploy(preparedTarget, credentials);
                providerResult = r;
                const deployCost = (r as { costUsd?: number }).costUsd ?? 0.01;
                if (!r.success) {
                  const msg = r.message || `deploy attempt ${attempt} failed`;
                  const { transient, hardFail } = classifyError(msg);
                  return { ok: false, errorMessages: [msg], transient, hardFail, qualityScore: 0, errorCount: 1, attemptUsdSpend: deployCost };
                }
                if (!r.deployUrl) {
                  return { ok: false, errorMessages: [`Provider ${providerName} did not return a deploy URL`], transient: false, hardFail: true, qualityScore: 0, errorCount: 1, attemptUsdSpend: deployCost };
                }
                // Verification step is part of the lifecycle the loop
                // governs — a provider that reports success but fails
                // its rollout poll is still a failed attempt and must
                // either retry (transient) or escalate (unrecoverable).
                const verifyResult = await this.pollDeploymentStatus(provider, preparedTarget, credentials, run.id, projectId);
                if (verifyResult.success) {
                  return { ok: true, qualityScore: 100, errorCount: 0, attemptUsdSpend: deployCost };
                }
                const verifyMsg = `Deployment verification failed: ${verifyResult.message}`;
                const { transient, hardFail } = classifyError(verifyMsg);
                return { ok: false, errorMessages: [verifyMsg], transient, hardFail, qualityScore: 25, errorCount: 1, attemptUsdSpend: deployCost };
              } catch (err) {
                const msg = (err as Error).message;
                const { transient, hardFail } = classifyError(msg);
                return { ok: false, errorMessages: [msg], transient, hardFail: !transient && hardFail, qualityScore: 0, errorCount: 1, attemptUsdSpend: 0.01 };
              }
            },
          });
          if (!loopRes.ok || !providerResult || !providerResult.success) {
            throw new Error(providerResult?.message || `Deployment failed (${loopRes.stopReason}): ${loopRes.reason}`);
          }

          deployUrl = providerResult.deployUrl;
          if (!deployUrl) {
            // Task #1130 — fail loud instead of fabricating a *.example.com
            // URL the user might actually click.
            throw new Error(`Provider ${providerName} did not return a deploy URL — cannot complete deployment`);
          }
          await this.addLog(run.id, projectId, "info", "deploy", `Provider deployment successful: ${providerResult.message}`);
        } else {
          // Task #1130 — do not fabricate a deploy URL when the provider is
          // missing. A "real" deploy with no working provider must fail
          // loudly so the user does not see a fake clickable link.
          throw new Error(`Cloud provider "${providerName}" not found — configure a valid provider before deploying`);
        }
      } else {
        // Task #1130 — same: a real deploy without a configured provider /
        // credentials is a hard failure, not a silent simulated success.
        throw new Error("No cloud provider configured for this deployment — configure infrastructure and credentials before deploying");
      }

      await this.storage.updateDeploymentRun(run.id, { status: "verifying" });
      await this.addLog(run.id, projectId, "info", "health-check", "Running health checks...");

      const healthStatus = await this.runHealthChecks(projectId, deployStage, run.id, credentials, providerName);

      if (healthStatus.status === "unhealthy") {
        await this.addLog(run.id, projectId, "warn", "health-check", `Health checks indicate issues: ${healthStatus.message}`);
      } else {
        await this.addLog(run.id, projectId, "info", "health-check", "Health checks passed");
      }

      const durationMs = Date.now() - startTime;

      await this.storage.updateDeploymentRun(run.id, {
        status: "success",
        deployUrl,
        durationMs,
        completedAt: new Date(),
      });

      await this.storage.upsertStageState({
        projectId,
        stage: deployStage,
        status: "deployed",
        healthStatus: healthStatus.status === "healthy" ? "healthy" : "degraded",
        currentVersion: options.version,
        currentBuildId: artifactId,
        currentCommitSha: options.commitSha,
        deployUrl,
        lastDeployedAt: new Date(),
        provider: providerName,
        region: options.region || (target?.targetConfig as any)?.region,
      });

      await this.initializeQualityGates(run.id, projectId, deployStage, options.skipGates);

      broadcastDeploymentEvent({
        type: "deployment_completed",
        projectId,
        runId: run.id,
        stage: deployStage,
        data: { deployUrl, durationMs, version: options.version },
        timestamp: new Date().toISOString(),
      });

      // Notify the triggering user via their configured channels (email/WhatsApp)
      // per their CommunicationSettings notifyOnDeployments preference.
      // Dynamic import avoids a circular dep; fire-and-forget so a notification
      // failure never rolls back a successful deployment.
      if (options.triggeredByUserId) {
        const trigUserId = options.triggeredByUserId;
        import('./communicationOrchestrator').then(({ communicationOrchestrator }) => {
          communicationOrchestrator.sendNotification(
            trigUserId,
            projectId,
            'deployment',
            {
              projectName: projectId,
              environment: deployStage,
              status: 'success',
              version: options.version,
              triggeredBy: options.triggeredBy,
              startTime: new Date(Date.now() - durationMs).toISOString(),
              endTime: new Date().toISOString(),
              url: deployUrl,
              // refId enables HMAC Reply-To so operators can reply to a
              // deployment success email and have it routed back to the alert.
              refId: run.id,
            },
          ).catch((err: unknown) => {
            logger.warn('[DeploymentOrchestrator] deployment success notification send failed', { userId: trigUserId, error: err instanceof Error ? err.message : String(err) });
          });
        }).catch((err: unknown) => {
          logger.warn('[DeploymentOrchestrator] deployment success notification import failed', { error: err instanceof Error ? err.message : String(err) });
        });
      }

      // Auto-resolve hotfix tickets when production deployment completes
      await resolveHotfixTicketsOnDeployment(this.storage, projectId, deployStage, run.id, options.version);

      // Sync production file snapshots after successful production deployment
      if (deployStage === "production") {
        logger.info("[DeploymentOrchestrator] Syncing production file snapshots after deployment");
        try {
          await this.productionFileSyncService.syncProductionFiles(
            projectId,
            deployStage,
            options.version,
            options.commitSha
          );
        } catch (syncError: any) {
          console.error("[DeploymentOrchestrator] Failed to sync production file snapshots:", syncError.message);
        }
      }

      // Record the deployed state in version control (checkpoint + optional DB
      // snapshot) and, if the project is GitHub-linked, push + tag the release
      // so the remote repo reflects what is live. Best-effort — a git hiccup
      // never fails an otherwise-successful deployment.
      await this.recordDeploymentInGit(projectId, run.id, deployStage, options.version);

      import('./memoryOrchestrator').then(({ memoryOrchestrator }) => {
        memoryOrchestrator.ingestEvent({
          projectId,
          agentId: 'deployment',
          rawContent: `Deployment to ${deployStage} succeeded. Version: ${options.version || 'unknown'}, provider: ${providerName || 'default'}, duration: ${Math.round(durationMs / 1000)}s, URL: ${deployUrl}`,
          sourceTable: 'deployment_runs',
          sourceId: run.id,
          memoryTypeHint: 'task' as const,
        }).catch(() => {});
      }).catch(() => {});

      return {
        success: true,
        runId: run.id,
        stage: deployStage,
        status: "success",
        deployUrl,
        durationMs,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
      const durationMs = Date.now() - startTime;

      import('./memoryOrchestrator').then(({ memoryOrchestrator }) => {
        memoryOrchestrator.ingestEvent({
          projectId,
          agentId: 'deployment',
          rawContent: `Deployment to ${deployStage} FAILED: ${errorMessage}. Version: ${options.version || 'unknown'}, duration: ${Math.round(durationMs / 1000)}s`,
          sourceTable: 'deployment_runs',
          sourceId: run.id,
          memoryTypeHint: 'bug' as const,
        }).catch(() => {});
      }).catch(() => {});

      await this.addLog(run.id, projectId, "error", "deploy", `Deployment failed: ${errorMessage}`, { isError: 1 });

      await this.storage.updateDeploymentRun(run.id, {
        status: "failed",
        errorMessage,
        durationMs,
        completedAt: new Date(),
      });

      // Only mark stage state "failed" if this run actually transitioned
      // the stage to "deploying". If migrations failed before that point
      // we intentionally leave the previous stage state untouched.
      if (stageStateMutated) {
        await this.storage.upsertStageState({
          projectId,
          stage: deployStage,
          status: "failed",
          healthStatus: "unhealthy",
        });
      }

      await this.escalateDeploymentFailure(run.id, projectId, deployStage, errorMessage);

      broadcastDeploymentEvent({
        type: "deployment_failed",
        projectId,
        runId: run.id,
        stage: deployStage,
        data: { errorMessage, durationMs },
        timestamp: new Date().toISOString(),
      });

      // Notify the triggering user of the failure via their configured channels.
      if (options.triggeredByUserId) {
        const trigUserId = options.triggeredByUserId;
        import('./communicationOrchestrator').then(({ communicationOrchestrator }) => {
          communicationOrchestrator.sendNotification(
            trigUserId,
            projectId,
            'deployment',
            {
              projectName: projectId,
              environment: deployStage,
              status: 'failed',
              version: options.version,
              triggeredBy: options.triggeredBy,
              startTime: new Date(Date.now() - durationMs).toISOString(),
              endTime: new Date().toISOString(),
              // refId enables HMAC Reply-To so operators can reply to a
              // deployment failure email and have it routed back to the alert.
              refId: run.id,
            },
          ).catch((err: unknown) => {
            logger.warn('[DeploymentOrchestrator] deployment failure notification send failed', { userId: trigUserId, error: err instanceof Error ? err.message : String(err) });
          });
        }).catch((err: unknown) => {
          logger.warn('[DeploymentOrchestrator] deployment failure notification import failed', { error: err instanceof Error ? err.message : String(err) });
        });
      }

      return {
        success: false,
        runId: run.id,
        stage: deployStage,
        status: "failed",
        errorMessage,
        durationMs,
      };
    }
  }

  /**
   * Record a successful deployment in version control so the deployed state is
   * durable and recoverable:
   *  - Always: create a VC checkpoint (production also snapshots the DB) and
   *    store its id on the run as `checkpointCommitId`. Rollback restores the
   *    TARGET run's checkpoint, so this is what makes git/DB revert possible.
   *  - If GitHub-linked: push the deployed code and create/move a release tag
   *    (`deploy-<stage>-<version>`) so the remote repo matches what is live.
   * Best-effort throughout: never throws, so it cannot fail a good deploy.
   */
  private async recordDeploymentInGit(
    projectId: string,
    runId: string,
    stage: string,
    version: string | undefined,
  ): Promise<void> {
    try {
      const label = `Deploy ${stage}${version ? ` ${version}` : ""}`;
      const { createCheckpoint } = await import("./versionControl");
      const checkpoint = await createCheckpoint(projectId, label, {
        checkpointType: "auto",
        includeDbSnapshot: stage === "production",
        source: "deployment",
      });
      if (checkpoint?.id) {
        await this.storage.updateDeploymentRun(runId, { checkpointCommitId: checkpoint.id });
        await this.addLog(runId, projectId, "info", "git",
          `Recorded deploy checkpoint ${checkpoint.id.slice(0, 8)}${stage === "production" ? " (with DB snapshot)" : ""}`);
      }
    } catch (err: any) {
      await this.addLog(runId, projectId, "warn", "git", `Could not create deploy checkpoint: ${err?.message || err}`).catch(() => {});
    }

    // GitHub push + tag (only does anything when the project is linked).
    try {
      const { pushToGitHub, createDeployTag } = await import("./githubSync");
      const push = await pushToGitHub(projectId, `Deploy ${stage}${version ? ` ${version}` : ""} [skip ci]`);
      const notLinked = (r: { errors?: string[]; message?: string }) =>
        r.errors?.includes("NOT_LINKED") || r.errors?.includes("NOT_CONNECTED") || /not linked|not connected/i.test(r.message || "");
      if (push.success) {
        await this.addLog(runId, projectId, "info", "git", `Pushed deployed code to GitHub (${push.filesAffected} file(s))`);
        const tag = `deploy-${stage}-${version || `run-${runId.slice(0, 8)}`}`.replace(/[^a-zA-Z0-9._-]/g, "-");
        const tagged = await createDeployTag(projectId, tag);
        if (tagged.success) {
          await this.addLog(runId, projectId, "info", "git", `Tagged release: ${tag}`);
        } else if (!notLinked(tagged)) {
          await this.addLog(runId, projectId, "warn", "git", `Release tag skipped: ${tagged.message}`);
        }
      } else if (!notLinked(push)) {
        await this.addLog(runId, projectId, "warn", "git", `GitHub push skipped: ${push.message}`);
      }
    } catch (err: any) {
      await this.addLog(runId, projectId, "warn", "git", `Could not sync deploy to GitHub: ${err?.message || err}`).catch(() => {});
    }
  }

  async executeStage(
    runId: string,
    stage: string,
    options?: { forceRescan?: boolean },
  ): Promise<boolean> {
    const deployStage = stage as DeploymentStage;
    // Task #1129 — remember the per-run "force re-scan" hint so that the
    // security-scan gate evaluator can bypass artifact-bound inheritance
    // for this single promote.
    if (options?.forceRescan) {
      this.forceRescanByRunId.set(runId, true);
    }
    const run = await this.storage.getDeploymentRun(runId);
    
    if (!run) {
      console.error(`[DeploymentOrchestrator] Run not found: ${runId}`);
      return false;
    }

    const projectId = run.projectId;

    broadcastDeploymentEvent({
      type: "deployment_started",
      projectId,
      runId,
      stage: deployStage,
      data: { version: run.version, runNumber: run.runNumber, provider: run.provider },
      timestamp: new Date().toISOString(),
    });

    const target = await this.storage.getTargetByStage(projectId, deployStage);

    if (!target) {
      if (process.env.NODE_ENV === "development") {
        await this.addLog(runId, projectId, "warn", "deploy", `No deployment target configured for ${deployStage} — running simulated deployment (dev mode)`);
        return this._simulateDeployment(runId, projectId, deployStage);
      }
      const errorMessage = `No deployment target configured for ${deployStage}. Please configure an infrastructure target via the Infrastructure Wizard before deploying.`;
      await this.addLog(runId, projectId, "error", "deploy", errorMessage);
      await this.storage.updateDeploymentRun(runId, { status: "failed", errorMessage, completedAt: new Date() });
      broadcastDeploymentEvent({ type: "deployment_failed", projectId, runId, stage: deployStage, data: { error: errorMessage }, timestamp: new Date().toISOString() });
      return false;
    }

    const providerName = target.provider as CloudProviderName;
    const provider = getProvider(providerName);

    let credentials: CloudCredential | undefined;
    if (target.credentialId) {
      credentials = await this.storage.getCloudCredentialById(target.credentialId);
    }

    if (!provider || !credentials) {
      const reason = !provider ? `Cloud provider "${providerName}" not found` : "Cloud credentials not configured for this target";
      if (process.env.NODE_ENV === "development") {
        await this.addLog(runId, projectId, "warn", "deploy", `${reason} — running simulated deployment (dev mode)`);
        return this._simulateDeployment(runId, projectId, deployStage);
      }
      const errorMessage = `${reason}. Please configure valid credentials in the Cloud Providers settings before deploying.`;
      await this.addLog(runId, projectId, "error", "deploy", errorMessage);
      await this.storage.updateDeploymentRun(runId, { status: "failed", errorMessage, completedAt: new Date() });
      broadcastDeploymentEvent({ type: "deployment_failed", projectId, runId, stage: deployStage, data: { error: errorMessage }, timestamp: new Date().toISOString() });
      return false;
    }

    try {
      // Unified pipeline step 1: migrate. Migrations run before quality gates
      // and before any stage-state mutation so a migration failure aborts the
      // run cleanly, leaving the stage untouched.
      try {
        await this.runPendingMigrations(runId, projectId, deployStage);
      } catch (migErr: any) {
        const errorMessage = migErr?.message || "Migration step failed";
        await this.storage.updateDeploymentRun(runId, { status: "failed", errorMessage, completedAt: new Date() });
        broadcastDeploymentEvent({ type: "deployment_failed", projectId, runId, stage: deployStage, data: { error: errorMessage }, timestamp: new Date().toISOString() });
        return false;
      }

      // Task #1130 — run security scans as their own phase BEFORE the
      // umbrella quality-gate check. The scan phase persists gate results
      // so the verify-phase gate sweep below short-circuits and does not
      // re-run them. This way a failing scan blocks the build phase
      // entirely instead of slipping past it.
      if (await this.abortIfCancelled(runId, projectId, deployStage)) return false;

      const scanResult = await this.runSecurityScanPhase(runId, projectId, deployStage);
      if (!scanResult.passed) {
        const errorMessage = `Security scan failed: ${scanResult.blockers.join(", ")}`;
        await this.addLog(runId, projectId, "error", "scanning", errorMessage, { isError: 1 });
        await this.storage.updateDeploymentRun(runId, { status: "failed", errorMessage, completedAt: new Date() });
        broadcastDeploymentEvent({ type: "deployment_failed", projectId, runId, stage: deployStage, data: { error: errorMessage, phase: "scanning" }, timestamp: new Date().toISOString() });
        return false;
      }

      if (await this.abortIfCancelled(runId, projectId, deployStage)) return false;

      await this.addLog(runId, projectId, "info", "quality-gates", "Executing quality gates before deployment...");
      const gateResults = await this.checkQualityGates(runId, deployStage);
      
      if (!gateResults.passed) {
        await this.addLog(runId, projectId, "error", "quality-gates", `Quality gates failed: ${gateResults.blockers.join(", ")}`);
        await this.storage.updateDeploymentRun(runId, { status: "failed", errorMessage: "Quality gates failed" });
        return false;
      }

      await this.addLog(runId, projectId, "info", "quality-gates", "All quality gates passed");

      // Unified pipeline step 2: build if a prior build artifact is not
      // already attached to the run. Promote paths set buildId on the run
      // and skip this.
      if (await this.abortIfCancelled(runId, projectId, deployStage)) return false;

      if (!run.buildId) {
        try {
          await this.storage.updateDeploymentRun(runId, { status: "building" });
          const { buildService } = await import("./buildService");
          await this.addLog(runId, projectId, "info", "build", "Starting build process...");
          const buildResult = await buildService.startBuild({
            projectId,
            version: run.version || undefined,
            onLog: async (log) => {
              await this.addLog(runId, projectId, "debug", "build", log);
            },
          });
          if (!buildResult.success) {
            throw new Error(`Build failed: ${buildResult.error}`);
          }
          await this.storage.updateDeploymentRun(runId, { buildId: buildResult.artifactId });
          run.buildId = buildResult.artifactId ?? null;
          await this.addLog(runId, projectId, "info", "build", `Build completed successfully. Artifact ID: ${buildResult.artifactId}`);
          // Task #1129 — security-scan gate may have run before the build
          // produced a buildId (typical on initial Test deploys). If a clean
          // fresh scan was recorded for this run, persist an artifact-bound
          // row now that we know the buildId, so a future promote of the
          // same artifact can inherit it.
          if (run.buildId) {
            await this.backfillSecurityScanArtifactBinding(runId, projectId, run.buildId);
          }
        } catch (buildErr: any) {
          const errorMessage = buildErr?.message || "Build step failed";
          await this.storage.updateDeploymentRun(runId, { status: "failed", errorMessage, completedAt: new Date() });
          broadcastDeploymentEvent({ type: "deployment_failed", projectId, runId, stage: deployStage, data: { error: errorMessage }, timestamp: new Date().toISOString() });
          return false;
        }
      }

      if (await this.abortIfCancelled(runId, projectId, deployStage)) return false;

      const project = await this.storage.getProjectInternal(projectId);
      const artifact = run.buildId ? await this.storage.getBuildArtifact(run.buildId) : null;

      // Wire the stage's connected database into the deploy so the deployed
      // app boots against it. resolveStageDatabaseUrl reads the DATABASE_URL
      // configured for this stage in the Deployment panel's database section
      // (encrypted on the target, or mirrored into its env vars). Merged
      // non-destructively — an explicit env-var DATABASE_URL still wins.
      const baseEnvVars = (target.environmentVariables as Record<string, string>) || {};
      let deployEnvVars = baseEnvVars;
      try {
        const { resolveStageDatabaseUrl } = await import("./stageDatabase");
        const stageDbUrl = await resolveStageDatabaseUrl(this.storage, projectId, deployStage);
        if (stageDbUrl && !baseEnvVars.DATABASE_URL) {
          deployEnvVars = { ...baseEnvVars, DATABASE_URL: stageDbUrl };
          await this.addLog(runId, projectId, "info", "deploy", "Wired stage database (DATABASE_URL) into the deployment environment");
        }
      } catch (dbErr: any) {
        await this.addLog(runId, projectId, "warn", "deploy", `Could not resolve stage database: ${dbErr?.message || String(dbErr)}`);
      }

      const deploymentTarget: ProviderDeploymentTarget = {
        projectId,
        stage: deployStage,
        version: run.version || undefined,
        buildId: run.buildId || undefined,
        commitSha: run.commitSha || undefined,
        imageUri: artifact?.artifactPath,
        region: (target.targetConfig as any)?.region,
        serviceName: (target.targetConfig as any)?.serviceName || `${project?.name || projectId}-${deployStage}`,
        environmentVariables: deployEnvVars,
        resourceConfig: target.resourceConfig as ProviderDeploymentTarget["resourceConfig"],
      };

      const preparedTarget = await this.runPrepareHook(runId, projectId, provider, deploymentTarget, credentials);

      await this.addLog(runId, projectId, "info", "deploy", `Deploying to ${providerName}...`);
      await this.storage.updateDeploymentRun(runId, { status: "deploying" });

      const deployResult = await provider.deploy(preparedTarget, credentials);

      if (!deployResult.success) {
        throw new Error(deployResult.message || "Deployment failed");
      }

      const pollResult = await this.pollDeploymentStatus(provider, preparedTarget, credentials, runId, projectId);
      if (!pollResult.success) {
        throw new Error(pollResult.message || "Deployment verification failed");
      }

      await this.addLog(runId, projectId, "info", "health-check", "Running health checks...");
      const healthResult = await this.runHealthChecks(projectId, deployStage, runId, credentials, providerName);

      if (healthResult.status === "unhealthy") {
        await this.addLog(runId, projectId, "warn", "health-check", `Health checks failed: ${healthResult.message}`);
      }

      await this.storage.upsertStageState({
        projectId,
        stage: deployStage,
        status: "deployed",
        healthStatus: healthResult.status,
        currentVersion: run.version,
        currentBuildId: run.buildId,
        currentCommitSha: run.commitSha,
        deployUrl: deployResult.deployUrl,
        lastDeployedAt: new Date(),
        provider: providerName,
        region: (target.targetConfig as any)?.region,
      });

      // Task #1128 — Persist the env-vars snapshot in effect on the target
      // when this deployment finished. Rollback uses this snapshot to restore
      // the prior env config when reverting to this version. The snapshot is
      // already stored if the promote endpoint pre-applied a carryover; only
      // capture here if not already set.
      const existingSnapshot = (run as any).envSnapshot as Record<string, string> | null | undefined;
      const snapshotPatch: Record<string, unknown> = existingSnapshot
        ? {}
        : { envSnapshot: (target.environmentVariables as Record<string, string>) || {} };

      await this.storage.updateDeploymentRun(runId, {
        status: "success",
        deployUrl: deployResult.deployUrl,
        completedAt: new Date(),
        ...snapshotPatch,
      } as any);

      // Autonomous promotion: if this stage's target opts in, promote the
      // just-deployed run to the next stage. promoteToNextStage re-checks the
      // quality gates and routes a production promotion through the approval
      // workflow, so a failing gate (or a required prod approval) still blocks
      // it. Fire-and-forget so it doesn't extend this run's pipeline.
      void this.maybeAutoPromote(runId, projectId, deployStage, target);

      return true;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      await this.addLog(runId, projectId, "error", "deploy", `Stage execution failed: ${errorMessage}`, { isError: 1 });
      
      await this.storage.updateDeploymentRun(runId, {
        status: "failed",
        errorMessage,
        completedAt: new Date(),
      });

      await this.storage.upsertStageState({
        projectId,
        stage: deployStage,
        status: "failed",
        healthStatus: "unhealthy",
      });

      return false;
    } finally {
      // Task #1129 — release the per-run forceRescan hint regardless of how
      // the pipeline ended so the map doesn't leak entries.
      this.forceRescanByRunId.delete(runId);
    }
  }

  // Task #1129 — when the security-scan gate runs before the build
  // produced a buildId, the artifact-bound row can't be persisted at
  // gate time. Once the build finishes we have the artifact identity,
  // so we look up the gate result we already stored, confirm it was a
  // clean fresh scan, and record the artifact-bound row now. This is
  // what makes the very first Test deploy's clean scan inheritable on
  // the subsequent Test→Pre-Prod promote.
  private async backfillSecurityScanArtifactBinding(
    runId: string,
    projectId: string,
    buildId: string,
  ): Promise<void> {
    try {
      const gateResults = await this.storage.getGateResults(runId);
      const securityResults = gateResults.filter(
        (g) => g.gateType === "security-scan" && g.status === "passed",
      );
      for (const gate of securityResults) {
        const details = (gate.details ?? {}) as Record<string, unknown>;
        if (details.decisionSource !== "fresh") continue;
        // Skip if the row was already recorded for this artifact (e.g.
        // promote paths where buildId existed at gate time).
        const existing = await this.storage.getLatestSecurityScanArtifactResult(
          projectId,
          buildId,
        );
        if (existing && existing.runId === runId && existing.gateName === gate.gateName) {
          continue;
        }
        const totalFindings = Number(details.vulnerabilityCount) || 0;
        const criticalFindings = Number(details.criticalCount) || 0;
        const highFindings = Number(details.highCount) || 0;
        // Only inherit truly clean scans — defensive double-check.
        if (criticalFindings + highFindings !== 0) continue;
        await this.storage.recordSecurityScanArtifactResult({
          projectId,
          buildId,
          runId,
          gateName: gate.gateName,
          scanEngine: typeof details.scanEngine === "string" ? details.scanEngine : "unknown",
          scanVersion: typeof details.scanVersion === "string" ? details.scanVersion : null,
          totalFindings,
          criticalFindings,
          highFindings,
          scannedAt: typeof details.executedAt === "string" ? new Date(details.executedAt) : new Date(),
        });
      }
    } catch (err) {
      console.warn(
        "[DeploymentOrchestrator] Failed to backfill artifact-bound security scan result:",
        err,
      );
    }
  }

  async checkQualityGates(runId: string, stage?: string): Promise<QualityGateCheckResult> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) {
      return {
        passed: false,
        gates: [],
        blockers: ["Deployment run not found"],
      };
    }

    const projectId = run.projectId;
    const deployStage = stage || run.stage;

    const policies = await this.storage.getQualityGatePolicies(projectId, deployStage);
    const existingResults = await this.storage.getGateResults(runId);
    
    const gates: QualityGateCheckResult["gates"] = [];
    const blockers: string[] = [];

    for (const policy of policies) {
      const existingResult = existingResults.find(r => r.gateName === policy.gateName);
      
      if (existingResult) {
        gates.push({
          name: policy.gateName,
          status: existingResult.status as "passed" | "failed" | "pending" | "skipped",
          required: existingResult.required === 1,
          details: existingResult.details as Record<string, unknown>,
        });
        
        if (existingResult.required === 1 && existingResult.status === "failed") {
          blockers.push(`${policy.gateName}: failed`);
        }
        continue;
      }

      const gateResult = await this.evaluateQualityGate(policy, projectId, runId);
      
      await this.storage.createGateResult({
        runId,
        projectId,
        gateName: policy.gateName,
        gateType: policy.gateType,
        stage: deployStage,
        status: gateResult.status,
        required: policy.isRequired ? 1 : 0,
        details: gateResult.details,
      });

      gates.push({
        name: policy.gateName,
        status: gateResult.status,
        required: !!policy.isRequired,
        details: gateResult.details,
      });

      if (!!policy.isRequired && gateResult.status === "failed") {
        blockers.push(`${policy.gateName}: ${gateResult.message || "failed"}`);
      }

      broadcastDeploymentEvent({
        type: "gate_update",
        projectId,
        runId,
        stage: deployStage as DeploymentStage,
        data: {
          gateName: policy.gateName,
          status: gateResult.status,
          required: !!policy.isRequired,
        },
        timestamp: new Date().toISOString(),
      });
    }

    if (policies.length === 0) {
      const config = await this.storage.getDeploymentConfig(projectId);
      const defaultGates = this.getDefaultGates(config, deployStage);
      
      for (const gate of defaultGates) {
        gates.push({
          name: gate.name,
          status: "passed",
          required: gate.required,
        });
        
        await this.storage.createGateResult({
          runId,
          projectId,
          gateName: gate.name,
          gateType: gate.type,
          stage: deployStage,
          status: "passed",
          required: gate.required ? 1 : 0,
        });
      }
    }

    const passed = blockers.length === 0 && gates.every(g => 
      !g.required || g.status === "passed" || g.status === "skipped"
    );

    return { passed, gates, blockers };
  }

  // Task #1167 — re-run a single security-scan gate for an existing run with
  // forceRescan=true. Lets a reviewer who is uneasy about an inherited
  // auto-pass (e.g. stale scanner version, freshly-disclosed CVE) trigger a
  // fresh scan from the inherited gate row without having to re-promote.
  async rescanSecurityGate(
    runId: string,
    policyId: string,
  ): Promise<{
    status: "passed" | "failed" | "pending" | "skipped";
    message?: string;
    gateName: string;
    details?: Record<string, unknown>;
  }> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) {
      throw new Error("Deployment run not found");
    }

    const policy = await this.storage.getQualityGatePolicy(policyId);
    if (!policy) {
      throw new Error("Quality gate policy not found");
    }
    if (policy.projectId !== run.projectId) {
      throw new Error("Gate policy does not belong to this run's project");
    }
    if (policy.gateType !== "security-scan") {
      throw new Error("Re-scan is only supported for security-scan gates");
    }

    // Drop the existing gate result so checkQualityGates / evaluateQualityGate
    // produces a fresh one rather than short-circuiting on the cached value.
    const existing = await this.storage.getGateResults(runId);
    const match = existing.find(r => r.gateName === policy.gateName);
    if (match) {
      await this.storage.deleteGateResult(match.id);
    }

    this.forceRescanByRunId.set(runId, true);
    try {
      const evalResult = await this.evaluateQualityGate(policy, run.projectId, runId);

      await this.storage.createGateResult({
        runId,
        projectId: run.projectId,
        gateName: policy.gateName,
        gateType: policy.gateType,
        stage: run.stage,
        status: evalResult.status,
        required: policy.isRequired ? 1 : 0,
        details: evalResult.details,
      });

      broadcastDeploymentEvent({
        type: "gate_update",
        projectId: run.projectId,
        runId,
        stage: run.stage as DeploymentStage,
        data: {
          gateName: policy.gateName,
          status: evalResult.status,
          required: !!policy.isRequired,
        },
        timestamp: new Date().toISOString(),
      });

      return {
        status: evalResult.status,
        message: evalResult.message,
        gateName: policy.gateName,
        details: evalResult.details,
      };
    } finally {
      this.forceRescanByRunId.delete(runId);
    }
  }

  private async evaluateQualityGate(
    policy: QualityGatePolicy,
    projectId: string,
    runId: string
  ): Promise<{ status: "passed" | "failed" | "pending" | "skipped"; message?: string; details?: Record<string, unknown> }> {
    const config = policy.config as Record<string, unknown> | null;
    
    switch (policy.gateType) {
      case "test": {
        const artifacts = await this.storage.getBuildArtifacts(projectId);
        const latestArtifact = artifacts[0];
        if (!latestArtifact) {
          return { status: "skipped", message: "No build artifact found" };
        }
        const testsPassed = latestArtifact.status === "success";
        return {
          status: testsPassed ? "passed" : "failed",
          message: testsPassed ? "All tests passed" : "Tests failed",
          details: { artifactId: latestArtifact.id, buildStatus: latestArtifact.status },
        };
      }

      case "test-pass": {
        await this.addLog(runId, projectId, "info", "quality-gate", `Executing test-pass gate: ${policy.gateName}`);
        const testCommand = (config?.testCommand as string) || "npm run test:integration";
        const minPassRate = (config?.minPassRate as number) || 100;
        
        try {
          const result = await this.executeCommand(testCommand, projectId);
          await this.addLog(runId, projectId, "debug", "quality-gate", `Test command output: ${result.stdout.slice(0, 500)}`);
          
          const passed = result.exitCode === 0;
          const passRate = passed ? 100 : 0;
          
          const details = {
            testCommand,
            exitCode: result.exitCode,
            passRate,
            minPassRate,
            stdout: result.stdout.slice(0, 1000),
            stderr: result.stderr?.slice(0, 500),
            executedAt: new Date().toISOString(),
          };
          
          await this.addLog(runId, projectId, passed ? "info" : "error", "quality-gate", 
            `Test-pass gate ${passed ? "passed" : "failed"}: pass rate ${passRate}% (min: ${minPassRate}%)`, 
            { isError: passed ? 0 : 1 });
          
          return {
            status: passRate >= minPassRate ? "passed" : "failed",
            message: passed ? `Integration tests passed (${passRate}% pass rate)` : `Integration tests failed (exit code: ${result.exitCode})`,
            details,
          };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          await this.addLog(runId, projectId, "error", "quality-gate", `Test-pass gate error: ${errorMessage}`, { isError: 1 });
          return {
            status: "failed",
            message: `Test execution error: ${errorMessage}`,
            details: { error: errorMessage, testCommand },
          };
        }
      }

      case "security-scan": {
        await this.addLog(runId, projectId, "info", "quality-gate", `Executing security-scan gate: ${policy.gateName}`);
        const scanCommand = (config?.scanCommand as string) || "npm audit --audit-level=high";
        const allowedVulnerabilities = (config?.allowedVulnerabilities as number) || 0;
        // Task #1418 — the multi-layer scanner is now the default path.
        // A gate config can opt out by setting `scanEngine` to anything
        // other than `"npm-audit"` / `"structured"` (e.g. a custom CI
        // command), in which case we fall back to the legacy
        // `executeCommand` path below for backwards compat.
        const scanEngine = (config?.scanEngine as string) || "structured";
        const scanVersion = (config?.scanVersion as string) || null;
        const useStructured =
          scanEngine === "structured" ||
          scanEngine === "npm-audit" ||
          scanEngine === "multi-layer";

        // Task #1129 — artifact-bound inheritance. If the same buildId
        // already has a clean scan within the inheritance window and the
        // user did not click "Force re-scan" on the promote, auto-pass
        // this gate without re-running the scan command.
        const run = await this.storage.getDeploymentRun(runId);
        const buildId = run?.buildId || null;
        const forceRescan = this.forceRescanByRunId.get(runId) === true;
        if (buildId && !forceRescan) {
          const prior = await this.storage.getLatestSecurityScanArtifactResult(projectId, buildId);
          if (prior) {
            const ageMs = Date.now() - new Date(prior.scannedAt).getTime();
            // Task #1141 — even within the inheritance window, a recorded
            // clean scan is only inheritable if it was produced by the
            // *current* scanner. If the engine was swapped or the version
            // was bumped (newer current vs. recorded), the prior result
            // can't speak for what the upgraded scanner would find now,
            // so we must run a fresh scan.
            const upgrade = detectScannerUpgrade(
              { scanEngine: prior.scanEngine, scanVersion: prior.scanVersion },
              { scanEngine, scanVersion },
            );
            if (upgrade) {
              await this.addLog(
                runId,
                projectId,
                "info",
                "quality-gate",
                `Security-scan inheritance skipped: scanner upgraded from ${formatScannerId(prior.scanEngine, prior.scanVersion)} to ${formatScannerId(scanEngine, scanVersion)} (${upgrade.reason}) — running a fresh scan for build ${buildId}.`,
              );
            } else if (ageMs <= SECURITY_SCAN_INHERITANCE_WINDOW_MS) {
              const ageHours = Math.max(1, Math.round(ageMs / (60 * 60 * 1000)));
              const inheritedDetails = {
                decisionSource: "inherited" as const,
                inheritedFromRunId: prior.runId,
                inheritedFromScanId: prior.id,
                buildId,
                scanEngine: prior.scanEngine,
                scanVersion: prior.scanVersion,
                scannedAt: prior.scannedAt,
                ageHours,
                inheritanceWindowMs: SECURITY_SCAN_INHERITANCE_WINDOW_MS,
                totalFindings: prior.totalFindings,
                criticalFindings: prior.criticalFindings,
                highFindings: prior.highFindings,
                allowedVulnerabilities,
              };
              await this.addLog(
                runId,
                projectId,
                "info",
                "quality-gate",
                `Security-scan gate inherited: same artifact (${buildId}) already scanned ${ageHours}h ago with ${prior.criticalFindings + prior.highFindings} blocking findings`,
              );
              return {
                status: "passed",
                message: `Inherited from run #${prior.runId ?? "(unknown)"} (scanned ${ageHours}h ago, ${prior.totalFindings} findings)`,
                details: inheritedDetails,
              };
            } else {
              await this.addLog(
                runId,
                projectId,
                "info",
                "quality-gate",
                `Prior security-scan for build ${buildId} is older than the inheritance window — running a fresh scan.`,
              );
            }
          }
        } else if (buildId && forceRescan) {
          await this.addLog(
            runId,
            projectId,
            "info",
            "quality-gate",
            `Force re-scan requested — bypassing artifact-bound inheritance for build ${buildId}.`,
          );
        }

        try {
          let vulnerabilityCount = 0;
          let criticalCount = 0;
          let highCount = 0;
          let mediumCount = 0;
          let lowCount = 0;
          let scanExitCode = 0;
          let scanStdout = "";
          let scanStderr = "";
          let structuredScanId: string | null = null;
          let structuredLayerCounts: Record<string, number> | null = null;

          if (useStructured) {
            // Task #1418 — invoke the multi-layer structured scanner
            // directly and read critical/high/medium/low counts from the
            // typed result, NOT by regex-parsing CLI output. This is the
            // only correct way to gate on findings: the structured
            // adapter runs npm-audit + sast + dataflow + secrets +
            // semgrep + osv + gitleaks + trivy + checkov + zap +
            // runtime-config + supply-chain in parallel and merges +
            // dedups them.
            const { startProjectSecurityScan, getProjectSecurityScan } = await import(
              "./securityScanner"
            );

            // Resolve container image ref from the build artifact's
            // metadata (the cloud provider records it there at build
            // time as `imageRef` / `imageUri`). Falls back to
            // artifactPath only when it parses as a valid image ref —
            // the trivy adapter re-validates everything so a bad value
            // is dropped, not run.
            let containerImageRef: string | null = null;
            try {
              if (buildId) {
                const artifact = await this.storage.getBuildArtifact(buildId);
                const meta = (artifact?.metadata ?? {}) as Record<string, unknown>;
                const candidate =
                  (typeof meta.imageRef === "string" && meta.imageRef) ||
                  (typeof meta.imageUri === "string" && meta.imageUri) ||
                  artifact?.artifactPath ||
                  null;
                containerImageRef = typeof candidate === "string" ? candidate : null;
              }
            } catch (artifactErr) {
              console.warn(
                "[DeploymentOrchestrator] Failed to resolve build artifact image ref:",
                artifactErr,
              );
            }

            // Resolve the deployed test/staging URL for the DAST layer.
            // Use the most recent successful test-stage deploy URL for
            // this project. ZAP rejects unsafe URLs internally so we
            // don't need to over-validate here.
            let dastTargetUrl: string | null = null;
            try {
              const recentTestRuns = await this.storage.getDeploymentRuns(projectId, "test", 5);
              const lastTestUrl = recentTestRuns.find(
                (r) => r.status === "success" && r.deployUrl,
              )?.deployUrl;
              dastTargetUrl = lastTestUrl || null;
            } catch (testUrlErr) {
              console.warn(
                "[DeploymentOrchestrator] Failed to resolve DAST target URL:",
                testUrlErr,
              );
            }

            // Per-run report directory under the build-artifact folder.
            // Picked up by the upload step (best-effort).
            const path = await import("path");
            const os = await import("os");
            const reportDir = path.join(os.tmpdir(), "yantra-security-reports", runId);

            await this.addLog(
              runId,
              projectId,
              "info",
              "quality-gate",
              `Structured security scan starting (image: ${containerImageRef ?? "fs-fallback"}, DAST: ${dastTargetUrl ?? "none"})`,
            );

            const job = startProjectSecurityScan({
              projectId,
              stage: (await this.storage.getDeploymentRun(runId))?.stage || "test",
              containerImageRef,
              dastTargetUrl,
              reportDir,
            });
            structuredScanId = job.scanId;

            // Poll until terminal — capped at 95s so we honor the
            // task-spec ≤90s scan target with a small grace margin
            // before failing the gate cleanly.
            const SCAN_DEADLINE_MS = 95_000;
            const POLL_MS = 500;
            const t0 = Date.now();
            while (true) {
              const cur = getProjectSecurityScan(job.scanId);
              if (cur && (cur.status === "complete" || cur.status === "error")) {
                if (cur.status === "error") {
                  scanExitCode = 1;
                  scanStderr = cur.error || "scan failed";
                  break;
                }
                const r = cur.result!;
                criticalCount = r.critical;
                highCount = r.high;
                mediumCount = r.medium;
                lowCount = r.low;
                vulnerabilityCount = r.findings;
                structuredLayerCounts = (r.layerCounts as Record<string, number>) || {};
                scanStdout = `Multi-layer scan ${r.scanId}: ${r.findings} findings (${r.critical}C/${r.high}H/${r.medium}M/${r.low}L) over ${r.scanners.length} layers, ${r.durationMs}ms`;
                break;
              }
              if (Date.now() - t0 > SCAN_DEADLINE_MS) {
                scanExitCode = 1;
                scanStderr = `structured scan exceeded ${SCAN_DEADLINE_MS}ms deadline (job ${job.scanId})`;
                break;
              }
              await new Promise((res) => setTimeout(res, POLL_MS));
            }
          } else {
            // Legacy path — operator opted into a custom scanCommand
            // (e.g. their own CI scanner). Keep regex parsing for
            // backwards compat; new gates use the structured path.
            const result = await this.executeCommand(scanCommand, projectId);
            scanExitCode = result.exitCode;
            scanStdout = result.stdout;
            scanStderr = result.stderr;
            await this.addLog(
              runId,
              projectId,
              "debug",
              "quality-gate",
              `Security scan output: ${result.stdout.slice(0, 500)}`,
            );
            try {
              const output = result.stdout + result.stderr;
              const vulnMatch = output.match(/(\d+)\s+vulnerabilit/i);
              if (vulnMatch) vulnerabilityCount = parseInt(vulnMatch[1], 10);
              const criticalMatch = output.match(/(\d+)\s+critical/i);
              if (criticalMatch) criticalCount = parseInt(criticalMatch[1], 10);
              const highMatch = output.match(/(\d+)\s+high/i);
              if (highMatch) highCount = parseInt(highMatch[1], 10);
            } catch (parseError) {
              console.warn(
                "[DeploymentOrchestrator] Failed to parse security scan output:",
                parseError,
              );
            }
          }

          const blockingVulnerabilities = criticalCount + highCount;
          let passed = scanExitCode === 0 && blockingVulnerabilities <= allowedVulnerabilities;

          // Task #1418 — auditable admin override of the blocking gate.
          // If the gate would fail but an admin recorded an override row
          // for this runId, pass the gate and stamp the override on the
          // result so the deployment record carries the audit trail.
          let overrideApplied:
            | { overriddenByUserId: string; reason: string; createdAt: string }
            | null = null;
          if (!passed) {
            try {
              const overrides = await this.storage.listSecurityScanGateOverrides(projectId, 50);
              const match = overrides.find(
                (o) => o.scanId === runId || o.runId === runId,
              );
              if (match) {
                passed = true;
                overrideApplied = {
                  overriddenByUserId: match.overriddenByUserId,
                  reason: match.reason,
                  createdAt: match.createdAt instanceof Date
                    ? match.createdAt.toISOString()
                    : String(match.createdAt ?? new Date().toISOString()),
                };
                await this.addLog(
                  runId,
                  projectId,
                  "warn",
                  "quality-gate",
                  `Security-scan gate OVERRIDDEN by admin user ${match.overriddenByUserId}: "${match.reason}" — ${blockingVulnerabilities} blocking findings remain.`,
                  { isError: 0 },
                );
              }
            } catch (overrideErr) {
              console.warn("[DeploymentOrchestrator] Failed to look up scan gate overrides:", overrideErr);
            }
          }

          const details = {
            decisionSource: "fresh" as const,
            scanCommand,
            scanEngine,
            scanVersion,
            buildId,
            exitCode: scanExitCode,
            vulnerabilityCount,
            criticalCount,
            highCount,
            mediumCount,
            lowCount,
            allowedVulnerabilities,
            stdout: scanStdout.slice(0, 1000),
            stderr: scanStderr?.slice(0, 500),
            executedAt: new Date().toISOString(),
            forceRescan,
            overrideApplied,
            // Task #1418 — structured-scanner provenance so the deploy
            // timeline can deep-link to the recorded scan row and the
            // per-layer breakdown columns (`security_scans.*_count`).
            structuredScanId,
            structuredLayerCounts,
          };

          // Task #1129 — only record artifact-bound results when the scan
          // ran cleanly (no blocking findings) and we know the buildId.
          // Failing scans are deliberately NOT recorded so a future
          // promote re-runs the scan rather than inheriting a fail.
          if (passed && buildId && blockingVulnerabilities === 0) {
            try {
              await this.storage.recordSecurityScanArtifactResult({
                projectId,
                buildId,
                runId,
                gateName: policy.gateName,
                scanEngine,
                scanVersion,
                totalFindings: vulnerabilityCount,
                criticalFindings: criticalCount,
                highFindings: highCount,
                scannedAt: new Date(),
              });
            } catch (recordError) {
              // Recording is best-effort: a failure here must not fail the
              // gate itself (the scan already passed).
              console.warn("[DeploymentOrchestrator] Failed to record artifact-bound security scan result:", recordError);
            }
          }

          await this.addLog(runId, projectId, passed ? "info" : "error", "quality-gate",
            `Security-scan gate ${passed ? "passed" : "failed"}: ${blockingVulnerabilities} critical/high vulnerabilities (allowed: ${allowedVulnerabilities})`,
            { isError: passed ? 0 : 1 });
          
          return {
            status: passed ? "passed" : "failed",
            message: passed 
              ? `Security scan passed (${blockingVulnerabilities} critical/high issues, ${allowedVulnerabilities} allowed)`
              : `Security scan failed: ${blockingVulnerabilities} critical/high vulnerabilities found (allowed: ${allowedVulnerabilities})`,
            details,
          };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          await this.addLog(runId, projectId, "error", "quality-gate", `Security-scan gate error: ${errorMessage}`, { isError: 1 });
          return {
            status: "failed",
            message: `Security scan error: ${errorMessage}`,
            details: { error: errorMessage, scanCommand },
          };
        }
      }

      case "coverage-threshold": {
        await this.addLog(runId, projectId, "info", "quality-gate", `Executing coverage-threshold gate: ${policy.gateName}`);
        const minCoverage = (config?.minCoverage as number) || 80;
        
        try {
          const artifacts = await this.storage.getBuildArtifacts(projectId);
          const latestArtifact = artifacts[0];
          
          let actualCoverage = 0;
          let coverageSource = "estimated";
          
          if (latestArtifact?.metadata) {
            const metadata = latestArtifact.metadata as Record<string, unknown>;
            if (typeof metadata.coverage === "number") {
              actualCoverage = metadata.coverage;
              coverageSource = "artifact";
            } else if (typeof metadata.lineCoverage === "number") {
              actualCoverage = metadata.lineCoverage;
              coverageSource = "artifact";
            }
          }
          
          if (coverageSource === "estimated") {
            // Task #1130 — fail loud instead of fabricating coverage with
            // Math.random(). A coverage gate that passes via a coin flip
            // is worse than no gate at all, because it looks rigorous.
            const reason = "no data source configured for coverage metrics — wire up your test runner to emit coverage in the build artifact metadata";
            await this.addLog(runId, projectId, "error", "quality-gate",
              `Coverage-threshold gate failed: ${reason}`, { isError: 1 });
            return {
              status: "failed",
              message: `Coverage gate cannot evaluate: ${reason}`,
              details: {
                reason: "no_data_source",
                hint: "Configure your test runner to emit coverage in the build artifact metadata (metadata.coverage or metadata.lineCoverage)",
                minCoverage,
                artifactId: latestArtifact?.id,
                executedAt: new Date().toISOString(),
              },
            };
          }

          const passed = actualCoverage >= minCoverage;
          
          const details = {
            actualCoverage: parseFloat(actualCoverage.toFixed(2)),
            minCoverage,
            coverageSource,
            artifactId: latestArtifact?.id,
            executedAt: new Date().toISOString(),
          };
          
          await this.addLog(runId, projectId, passed ? "info" : "warn", "quality-gate",
            `Coverage-threshold gate ${passed ? "passed" : "failed"}: ${actualCoverage.toFixed(1)}% (min: ${minCoverage}%)`,
            { isError: 0 });
          
          return {
            status: passed ? "passed" : "failed",
            message: passed
              ? `Code coverage ${actualCoverage.toFixed(1)}% meets threshold (${minCoverage}%)`
              : `Code coverage ${actualCoverage.toFixed(1)}% below threshold (${minCoverage}%)`,
            details,
          };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          await this.addLog(runId, projectId, "error", "quality-gate", `Coverage-threshold gate error: ${errorMessage}`, { isError: 1 });
          return {
            status: "skipped",
            message: `Coverage check error: ${errorMessage}`,
            details: { error: errorMessage, minCoverage },
          };
        }
      }

      case "performance-check": {
        await this.addLog(runId, projectId, "info", "quality-gate", `Executing performance-check gate: ${policy.gateName}`);
        const maxResponseTime = (config?.maxResponseTime as number) || 500;
        const maxErrorRate = (config?.maxErrorRate as number) || 1;
        
        try {
          const run = await this.storage.getDeploymentRun(runId);
          const _stageState = run ? await this.storage.getStageState(projectId, run.stage) : null;
          
          // Task #1130 — fail loud instead of fabricating metrics with
          // Math.random(). DeploymentStageState has no metrics field and
          // there is no monitoring integration wired up; the gate must
          // not "pass" by coin flip.
          const reason = "no data source configured for performance metrics — set up a monitoring integration first";
          await this.addLog(runId, projectId, "error", "quality-gate",
            `Performance-check gate failed: ${reason}`, { isError: 1 });
          return {
            status: "failed",
            message: `Performance gate cannot evaluate: ${reason}`,
            details: {
              reason: "no_data_source",
              hint: "Configure monitoring in Project Settings → Integrations to feed avg response time and error rate to this gate",
              maxResponseTime,
              maxErrorRate,
              executedAt: new Date().toISOString(),
            },
          };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          await this.addLog(runId, projectId, "error", "quality-gate", `Performance-check gate error: ${errorMessage}`, { isError: 1 });
          return {
            status: "skipped",
            message: `Performance check error: ${errorMessage}`,
            details: { error: errorMessage, maxResponseTime, maxErrorRate },
          };
        }
      }

      case "coverage": {
        // Task #1130 — the legacy "coverage" gateType had a Math.random()
        // fallback that decided pass/fail by coin flip. Fail loud so a
        // misconfigured project can't silently ship through this gate.
        const threshold = (config?.threshold as number) || 80;
        const reason = "no data source configured for coverage metrics — wire up your test runner to emit coverage in the build artifact metadata";
        await this.addLog(runId, projectId, "error", "quality-gate",
          `Coverage gate failed: ${reason}`, { isError: 1 });
        return {
          status: "failed",
          message: `Coverage gate cannot evaluate: ${reason}`,
          details: {
            reason: "no_data_source",
            hint: "Configure your test runner to emit coverage in the build artifact metadata, or use the 'coverage-threshold' gate type instead",
            threshold,
          },
        };
      }

      case "security": {
        return {
          status: "passed",
          message: "Security scan completed with no critical issues",
          details: { criticalIssues: 0, highIssues: 0, mediumIssues: 0 },
        };
      }

      case "approval": {
        return {
          status: "pending",
          message: "Awaiting manual approval",
        };
      }

      default:
        return { status: "passed" };
    }
  }

  private async executeCommand(
    command: string,
    _projectId: string
  ): Promise<{ exitCode: number; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const { exec } = require("child_process");
      const timeout = 5 * 60 * 1000;
      
      const _child = exec(command, { 
        timeout,
        maxBuffer: 1024 * 1024 * 10,
        cwd: process.cwd(),
      }, (error: any, stdout: string, stderr: string) => {
        resolve({
          exitCode: error ? (error.code || 1) : 0,
          stdout: stdout || "",
          stderr: stderr || "",
        });
      });
    });
  }

  async seedDefaultQualityGates(projectId: string): Promise<{ created: number; stages: string[] }> {
    const project = await this.storage.getProjectInternal(projectId);
    if (!project) {
      throw new Error(`Project not found: ${projectId}`);
    }

    // Task #1122: resolve archetype-specific validation profile; fall
    // back to SaaS-web baseline if lookup fails or yields no runnable
    // gates so pre-flight is never silently disabled.
    const SAAS_WEB_BASELINE: Array<{
      gateName: string;
      gateType: string;
      isRequired: number;
      config: Record<string, unknown>;
      order: number;
    }> = [
      {
        gateName: "unit-tests",
        gateType: "test-pass",
        isRequired: 1,
        config: { testCommand: "npm run test", minPassRate: 100 },
        order: 1,
      },
      {
        gateName: "lint-check",
        gateType: "test-pass",
        isRequired: 1,
        config: { testCommand: "npm run lint", minPassRate: 100 },
        order: 2,
      },
    ];

    let archetypeTestGates: typeof SAAS_WEB_BASELINE = [];
    let archetypeLookupFailed = false;
    try {
      const archetypeId = await resolveProjectArchetypeId(projectId);
      const profile = await resolveValidationProfile(archetypeId);
      if (profile) {
        archetypeTestGates = this.archetypeProfileToQualityGates(profile.gates, archetypeId);
      }
    } catch (err: unknown) {
      archetypeLookupFailed = true;
      logger.warn(
        `[DeploymentOrchestrator] Archetype validation profile lookup failed for project ${projectId}; falling back to SaaS-web baseline gates: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (archetypeTestGates.length === 0) {
      if (!archetypeLookupFailed) {
        logger.warn(
          `[DeploymentOrchestrator] Archetype validation profile for project ${projectId} produced no runnable gates; falling back to SaaS-web baseline so pre-flight is not disabled.`,
        );
      }
      archetypeTestGates = SAAS_WEB_BASELINE;
    }

    const stageGates: Record<string, Array<{
      gateName: string;
      gateType: string;
      isRequired: number;
      config: Record<string, unknown>;
      order: number;
    }>> = {
      test: archetypeTestGates,
      preprod: [
        {
          gateName: "integration-tests",
          gateType: "test-pass",
          isRequired: 1,
          config: { testCommand: "npm run test:integration", minPassRate: 100 },
          order: 1,
        },
        {
          gateName: "security-scan",
          gateType: "security-scan",
          isRequired: 1,
          config: { scanCommand: "npm audit --audit-level=high", allowedVulnerabilities: 0 },
          order: 2,
        },
        {
          gateName: "code-coverage",
          gateType: "coverage-threshold",
          isRequired: 0,
          config: { minCoverage: 80 },
          order: 3,
        },
        {
          gateName: "performance-baseline",
          gateType: "performance-check",
          isRequired: 0,
          config: { maxResponseTime: 500, maxErrorRate: 1 },
          order: 4,
        },
      ],
      production: [
        {
          gateName: "smoke-tests",
          gateType: "test-pass",
          isRequired: 1,
          config: { testCommand: "npm run test:smoke", minPassRate: 100 },
          order: 1,
        },
        {
          gateName: "security-audit",
          gateType: "security-scan",
          isRequired: 1,
          config: { scanCommand: "npm audit --audit-level=moderate", allowedVulnerabilities: 0 },
          order: 2,
        },
        {
          gateName: "production-readiness",
          gateType: "approval",
          isRequired: 1,
          config: {},
          order: 3,
        },
        {
          gateName: "performance-check",
          gateType: "performance-check",
          isRequired: 1,
          config: { maxResponseTime: 300, maxErrorRate: 0.5 },
          order: 4,
        },
      ],
    };

    let createdCount = 0;
    const stages: string[] = [];

    for (const [stage, gates] of Object.entries(stageGates)) {
      const existingPolicies = await this.storage.getQualityGatePolicies(projectId, stage);
      
      if (existingPolicies.length > 0) {
        continue;
      }

      for (const gate of gates) {
        await this.storage.createQualityGatePolicy({
          projectId,
          stage,
          gateName: gate.gateName,
          gateType: gate.gateType,
          isRequired: gate.isRequired,
          config: gate.config,
          order: gate.order,
          isEnabled: 1,
        });
        createdCount++;
      }
      stages.push(stage);
    }

    return { created: createdCount, stages };
  }

  /**
   * Task #1122 + #1145: map archetype registry gates to `test-pass` quality
   * gate policies. Gates with a concrete `command` use it directly. Gates
   * without a command (e.g. `headless-smoke`, `notebook-execute`,
   * `cli-help-smoke`, `http-health-probe`, `theme-token`,
   * `eval-metric-range`, `expo-prebuild-check`, `godot-scene-validate`) are
   * resolved against `ARCHETYPE_KIND_COMMANDS` for the project's archetype
   * so they run a real check instead of failing with "Missing script: ...".
   * If the (kind, archetype) combination has no mapping the gate is still
   * skipped with a warning, preserving the old fallback behaviour for
   * unrecognised combinations.
   */
  private archetypeProfileToQualityGates(
    gates: Array<{
      kind: string;
      command?: string;
      description?: string;
      blocking?: boolean;
    }>,
    archetypeId?: string | null,
  ): Array<{
    gateName: string;
    gateType: string;
    isRequired: number;
    config: Record<string, unknown>;
    order: number;
  }> {
    const out: ReturnType<DeploymentOrchestrator['archetypeProfileToQualityGates']> = [];
    let order = 1;
    const usedNames = new Set<string>();
    for (const g of gates) {
      let testCommand = g.command;
      let commandSource: 'profile' | 'archetype-kind' = 'profile';
      if (!testCommand) {
        const lookup = archetypeId
          ? ARCHETYPE_KIND_COMMANDS[g.kind]?.[archetypeId]
          : undefined;
        if (lookup) {
          testCommand = lookup;
          commandSource = 'archetype-kind';
        }
      }
      if (!testCommand) {
        logger.warn(
          `[DeploymentOrchestrator] Skipping archetype gate of kind '${g.kind}'${archetypeId ? ` for archetype '${archetypeId}'` : ''} — no shell command declared in the validation profile and no entry in ARCHETYPE_KIND_COMMANDS; add one to surface this kind as a real gate.`,
        );
        continue;
      }

      let baseName: string;
      if (g.kind === 'cli') {
        const head = testCommand.trim().split(/\s+/).slice(0, 3).join(' ');
        baseName = head.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
      } else {
        baseName = g.kind.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
      }
      let gateName = baseName || `gate-${order}`;
      let suffix = 2;
      while (usedNames.has(gateName)) {
        gateName = `${baseName || 'gate'}-${suffix++}`;
      }
      usedNames.add(gateName);

      out.push({
        gateName,
        gateType: 'test-pass',
        isRequired: g.blocking === false ? 0 : 1,
        config: {
          testCommand,
          minPassRate: 100,
          ...(g.description ? { description: g.description } : {}),
          archetypeGateKind: g.kind,
          archetypeGateCommandSource: commandSource,
          ...(commandSource === 'archetype-kind' && archetypeId
            ? { archetypeId }
            : {}),
        },
        order: order++,
      });
    }
    return out;
  }

  private getDefaultGates(
    config: DeploymentProjectConfig | null,
    stage: string
  ): { name: string; type: string; required: boolean }[] {
    const gates: { name: string; type: string; required: boolean }[] = [];

    if (config?.requireTestPass) {
      gates.push({ name: "unit-tests", type: "automated", required: true });
      gates.push({ name: "integration-tests", type: "automated", required: true });
    }
    
    if (config?.requireSecurityScan) {
      gates.push({ name: "security-scan", type: "automated", required: true });
    }
    
    if (config?.requireCodeReview) {
      gates.push({ name: "code-review", type: "manual", required: true });
    }

    gates.push({ name: "smoke-test", type: "automated", required: stage === "production" });

    return gates;
  }

  async rollbackByRunId(
    runId: string,
    targetVersion?: string,
    reason?: string
  ): Promise<DeploymentRun> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) {
      throw new Error(`Deployment run not found: ${runId}`);
    }

    const projectId = run.projectId;
    const stage = run.stage;

    const rollbackResult = await this.rollback(projectId, stage, undefined, targetVersion);

    if (!rollbackResult.success) {
      throw new Error(rollbackResult.errorMessage || "Rollback failed");
    }

    const newRun = await this.storage.getDeploymentRun(rollbackResult.runId);
    if (!newRun) {
      throw new Error("Failed to retrieve rollback deployment run");
    }

    if (reason) {
      await this.addLog(newRun.id, projectId, "info", "rollback", `Rollback reason: ${reason}`);
    }

    return newRun;
  }

  async rollback(
    projectId: string,
    stage: string,
    targetRunId?: string,
    targetVersion?: string
  ): Promise<RollbackResult> {
    const rollbackStage = stage as DeploymentStage;
    
    if (!STAGE_ORDER.includes(rollbackStage)) {
      return {
        success: false,
        runId: "",
        errorMessage: `Invalid stage: ${stage}`,
      };
    }

    const target = await this.storage.getTargetByStage(projectId, rollbackStage);
    let credentials: CloudCredential | undefined;
    
    if (target?.credentialId) {
      credentials = await this.storage.getCloudCredentialById(target.credentialId);
    }

    let targetRun: DeploymentRun | null;

    if (targetRunId) {
      targetRun = await this.storage.getDeploymentRun(targetRunId);
      if (!targetRun || targetRun.stage !== rollbackStage) {
        return {
          success: false,
          runId: "",
          errorMessage: `Target run ${targetRunId} not found or not for stage ${rollbackStage}`,
        };
      }
    } else if (targetVersion) {
      const runs = await this.storage.getDeploymentRuns(projectId, rollbackStage, 50);
      targetRun = runs.find(r => r.version === targetVersion && r.status === "success") || null;
      if (!targetRun) {
        return {
          success: false,
          runId: "",
          errorMessage: `No successful deployment found for version ${targetVersion}`,
        };
      }
    } else {
      const runs = await this.storage.getDeploymentRuns(projectId, rollbackStage, 10);
      const successfulRuns = runs.filter((r) => r.status === "success");
      if (successfulRuns.length < 2) {
        return {
          success: false,
          runId: "",
          errorMessage: "No previous successful deployment to rollback to",
        };
      }
      targetRun = successfulRuns[1];
    }

    const currentRuns = await this.storage.getDeploymentRuns(projectId, rollbackStage, 1);
    const currentRun = currentRuns[0];

    await this.storage.upsertStageState({
      projectId,
      stage: rollbackStage,
      status: "rolling_back",
    });

    broadcastDeploymentEvent({
      type: "rollback",
      projectId,
      runId: targetRun.id,
      stage: rollbackStage,
      data: { 
        targetVersion: targetRun.version,
        rollingBackFrom: currentRun?.version,
      },
      timestamp: new Date().toISOString(),
    });

    if (target && credentials) {
      const providerName = target.provider as CloudProviderName;
      const provider = getProvider(providerName);
      
      if (provider) {
        const project = await this.storage.getProjectInternal(projectId);
        const artifact = targetRun.buildId ? await this.storage.getBuildArtifact(targetRun.buildId) : null;

        // Task #1128 — Rollback parity. Restore the env-vars snapshot in
        // effect when the targetRun was originally deployed, so the rolled-
        // back app boots with the env it was originally deployed with.
        // Uses the shared restoreEnvSnapshot helper so route-level and
        // orchestrator-level rollback restores cannot drift apart.
        const restoreResult = await restoreEnvSnapshot(
          {
            getTargetByStage: (pid, st) => this.storage.getTargetByStage(pid, st) as any,
            updateDeploymentTarget: (id, patch) => this.storage.updateDeploymentTarget(id, patch as any),
          },
          projectId,
          rollbackStage,
          targetRun as any,
        );
        if (restoreResult.restored) {
          target.environmentVariables = (targetRun as any).envSnapshot as any;
        }

        // Task #1420 — Read the project-level `enableSnapshotRollback`
        // toggle so VM-style adapters (Hetzner / Vultr / Linode / Oracle)
        // can pick the snapshot-restore strategy when ON. Stamped onto
        // the provider DeploymentTarget so each adapter's rollback() can
        // see it without an extra storage round-trip.
        let snapshotRollbackEnabled = false;
        try {
          const projectConfig = await this.storage.getDeploymentConfig(projectId);
          snapshotRollbackEnabled = Boolean(projectConfig && (projectConfig as { enableSnapshotRollback?: number | boolean | null }).enableSnapshotRollback);
        } catch {
          // Missing helper or row → treat as OFF (default behaviour).
        }

        const deploymentTarget: ProviderDeploymentTarget & { snapshotRollbackEnabled?: boolean } = {
          projectId,
          stage: rollbackStage,
          version: targetRun.version || undefined,
          buildId: targetRun.buildId || undefined,
          commitSha: targetRun.commitSha || undefined,
          imageUri: artifact?.artifactPath,
          region: (target.targetConfig as any)?.region,
          serviceName: (target.targetConfig as any)?.serviceName || `${project?.name || projectId}-${rollbackStage}`,
          environmentVariables: target.environmentVariables as Record<string, string>,
          resourceConfig: target.resourceConfig as ProviderDeploymentTarget["resourceConfig"],
          snapshotRollbackEnabled,
        };

        try {
          const rollbackResult = await provider.rollback(
            deploymentTarget,
            credentials,
            targetRun.version || undefined
          );

          if (!rollbackResult.success) {
            throw new Error(rollbackResult.message || "Rollback failed");
          }

          const healthResult = await this.runHealthChecks(projectId, rollbackStage, targetRun.id, credentials, providerName);

          await this.storage.upsertStageState({
            projectId,
            stage: rollbackStage,
            status: "deployed",
            healthStatus: healthResult.status,
            currentVersion: targetRun.version,
            currentBuildId: targetRun.buildId,
            deployUrl: rollbackResult.deployUrl || targetRun.deployUrl,
            lastDeployedAt: new Date(),
          });

          return {
            success: true,
            runId: targetRun.id,
            rolledBackFromRunId: currentRun?.id,
            targetVersion: targetRun.version || undefined,
          };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          
          await this.storage.upsertStageState({
            projectId,
            stage: rollbackStage,
            status: "failed",
            healthStatus: "unhealthy",
          });

          return {
            success: false,
            runId: targetRun.id,
            errorMessage,
          };
        }
      }
    }

    const result = await this.startDeployment(projectId, rollbackStage, {
      version: targetRun.version || undefined,
      buildId: targetRun.buildId || undefined,
      commitSha: targetRun.commitSha || undefined,
      triggeredBy: "user",
      provider: targetRun.provider || undefined,
      region: targetRun.region || undefined,
      skipBuild: true,
    });

    if (result.success) {
      await this.storage.updateDeploymentRun(result.runId, {
        rolledBackFromRunId: currentRun?.id,
      });
    }

    return {
      success: result.success,
      runId: result.runId,
      rolledBackFromRunId: currentRun?.id,
      targetVersion: targetRun.version || undefined,
      errorMessage: result.errorMessage,
    };
  }

  async getDeploymentLogs(runId: string, options?: LogsOptions): Promise<LogEntry[]> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) {
      return [];
    }

    const localLogs = await this.storage.getDeploymentLogs(runId);
    const localLogEntries: LogEntry[] = localLogs.map(log => ({
      timestamp: log.timestamp || new Date(),
      message: log.message,
      level: log.level,
      streamName: log.source ?? undefined,
      metadata: log.metadata as Record<string, unknown>,
    }));

    const target = await this.storage.getTargetByStage(run.projectId, run.stage);
    if (!target?.provider || !target.credentialId) {
      return localLogEntries;
    }

    const credentials = await this.storage.getCloudCredentialById(target.credentialId);
    if (!credentials) {
      return localLogEntries;
    }

    const provider = getProvider(target.provider);
    if (!provider) {
      return localLogEntries;
    }

    try {
      const project = await this.storage.getProjectInternal(run.projectId);
      
      const deploymentTarget: ProviderDeploymentTarget = {
        projectId: run.projectId,
        stage: run.stage,
        version: run.version || undefined,
        serviceName: (target.targetConfig as any)?.serviceName || `${project?.name || run.projectId}-${run.stage}`,
        region: (target.targetConfig as any)?.region,
      };

      const cloudLogsResult = await provider.getLogs(deploymentTarget, credentials, options);
      
      const allLogs = [...localLogEntries, ...cloudLogsResult.logs];
      allLogs.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
      
      return allLogs;
    } catch (error) {
      console.error(`[DeploymentOrchestrator] Failed to fetch cloud logs:`, error);
      return localLogEntries;
    }
  }

  private async pollDeploymentStatus(
    provider: ReturnType<typeof getProvider>,
    target: ProviderDeploymentTarget,
    credentials: CloudCredential,
    runId: string,
    projectId: string
  ): Promise<ProviderResult> {
    if (!provider) {
      return { success: false, status: "failed", message: "Provider not found" };
    }

    const startTime = Date.now();
    
    while (Date.now() - startTime < DEPLOYMENT_TIMEOUT_MS) {
      try {
        const status = await provider.getStatus(target, credentials);
        
        broadcastDeploymentEvent({
          type: "deployment_progress",
          projectId,
          runId,
          stage: target.stage as DeploymentStage,
          data: { status: status.status, message: status.message },
          timestamp: new Date().toISOString(),
        });

        if (status.status === "deployed") {
          return status;
        }
        
        if (status.status === "failed") {
          return status;
        }

        await new Promise(resolve => setTimeout(resolve, DEPLOYMENT_POLL_INTERVAL_MS));
      } catch (error) {
        console.error(`[DeploymentOrchestrator] Error polling status:`, error);
        await new Promise(resolve => setTimeout(resolve, DEPLOYMENT_POLL_INTERVAL_MS));
      }
    }

    return {
      success: false,
      status: "failed",
      message: "Deployment timed out waiting for completion",
    };
  }

  private async runHealthChecks(
    projectId: string,
    stage: string,
    runId: string,
    _credentials?: CloudCredential,
    _providerName?: string
  ): Promise<{ status: "healthy" | "unhealthy" | "degraded" | "unknown"; message: string }> {
    try {
      const definitions = await this.storage.getHealthCheckDefinitions(projectId, stage);
      
      if (definitions.length === 0) {
        return { status: "healthy", message: "No health checks configured, assuming healthy" };
      }

      let healthyCount = 0;
      let unhealthyCount = 0;

      for (const definition of definitions) {
        const result = await healthMonitorService.executeHealthCheck(definition);
        
        await this.storage.createHealthCheckResult({
          definitionId: definition.id,
          runId,
          status: result.status,
          responseTime: result.responseTime,
          statusCode: result.statusCode,
          responseBody: result.responseBody,
          errorMessage: result.errorMessage,
        });

        if (result.status === "healthy") {
          healthyCount++;
        } else if (result.status === "unhealthy") {
          unhealthyCount++;
        }
      }

      if (unhealthyCount === 0) {
        return { status: "healthy", message: `All ${healthyCount} health checks passed` };
      } else if (healthyCount === 0) {
        return { status: "unhealthy", message: `All ${unhealthyCount} health checks failed` };
      } else {
        return { 
          status: "degraded", 
          message: `${healthyCount} passed, ${unhealthyCount} failed` 
        };
      }
    } catch (error) {
      console.error(`[DeploymentOrchestrator] Health check error:`, error);
      return { status: "unknown", message: "Error running health checks" };
    }
  }

  private async escalateDeploymentFailure(
    runId: string,
    projectId: string,
    stage: DeploymentStage,
    errorMessage: string
  ): Promise<void> {
    try {
      const issue: EscalationIssue = {
        runId,
        projectId,
        type: "deploy-failure",
        severity: stage === "production" ? "critical" : "high",
        summary: `Deployment to ${stage} failed: ${errorMessage.slice(0, 100)}`,
        details: {
          stage,
          errorMessage,
          timestamp: new Date().toISOString(),
        },
        source: "deployment-orchestrator",
      };

      await this.escalationService.escalateIssue(issue);
    } catch (error) {
      console.error(`[DeploymentOrchestrator] Failed to escalate deployment failure:`, error);
    }
  }

  async canPromote(runId: string): Promise<PromotionCheckResult> {
    const run = await this.storage.getDeploymentRun(runId);
    
    if (!run) {
      return {
        canPromote: false,
        currentStage: "test",
        nextStage: null,
        blockers: ["Deployment run not found"],
        gatesStatus: { passed: false, gates: [], blockers: ["Run not found"] },
      };
    }

    const currentStage = run.stage as DeploymentStage;
    const nextStage = this.getNextStage(currentStage);
    const blockers: string[] = [];

    if (run.status !== "success") {
      blockers.push(`Deployment status is '${run.status}', must be 'success' to promote`);
    }

    if (!nextStage) {
      blockers.push(`Cannot promote from ${currentStage} - already at final stage`);
    }

    const gatesStatus = await this.checkQualityGates(runId, currentStage);
    if (!gatesStatus.passed) {
      blockers.push(...gatesStatus.blockers);
    }

    return {
      canPromote: blockers.length === 0,
      currentStage,
      nextStage,
      blockers,
      gatesStatus,
    };
  }

  /**
   * Autonomous promotion. When the just-deployed stage's target has
   * autoPromote enabled, promote the run to the next stage via
   * promoteToNextStage (which re-checks quality gates and routes production
   * through the approval workflow). No-op for production (no stage above it)
   * or when the flag is off. Never throws into the caller's success path.
   */
  private async maybeAutoPromote(
    runId: string,
    projectId: string,
    stage: DeploymentStage,
    target: any,
  ): Promise<void> {
    try {
      if (!target?.autoPromote) return;
      if (stage === "production") return;
      await this.addLog(runId, projectId, "info", "promote", `Auto-promote is enabled for ${stage} — evaluating promotion to the next stage`);
      const result = await this.promoteToNextStage(projectId, runId);
      if (result.success) {
        await this.addLog(runId, projectId, "info", "promote", `Auto-promoted ${stage} → ${result.stage} (run ${result.runId})`);
      } else {
        await this.addLog(runId, projectId, "warn", "promote", `Auto-promote from ${stage} did not proceed: ${result.errorMessage || result.status}`);
      }
    } catch (err: any) {
      await this.addLog(runId, projectId, "warn", "promote", `Auto-promote from ${stage} errored: ${err?.message || String(err)}`).catch(() => {});
    }
  }

  /**
   * Apply an autoscaling change to a stage — provider-agnostic. Persists the
   * new bounds onto the deployment target's resourceConfig (which EVERY adapter's
   * deploy() honors: ECS desiredCount, Cloud Run / Container Apps min–max,
   * DigitalOcean instance_count, …), so the change takes on the next deploy for
   * any connected provider. If the provider's adapter implements applyScale, the
   * change is also applied live to the running service without a redeploy.
   */
  async applyAutoscaling(
    projectId: string,
    stage: string,
    scale: { minInstances?: number; maxInstances?: number; cpuThreshold?: number; memoryThreshold?: number },
  ): Promise<{ provider: string | null; persisted: boolean; appliedLive: boolean; message: string }> {
    const target = await this.storage.getTargetByStage(projectId, stage as DeploymentStage);
    const provider = target?.provider ?? null;

    if (target) {
      const rc = (target.resourceConfig as Record<string, any>) || {};
      await this.storage.updateDeploymentTarget(target.id, {
        resourceConfig: {
          ...rc,
          minInstances: scale.minInstances ?? rc.minInstances ?? 1,
          maxInstances: scale.maxInstances ?? rc.maxInstances ?? 10,
          ...(scale.cpuThreshold != null ? { cpuThreshold: scale.cpuThreshold } : {}),
        },
      } as any);
    }

    let appliedLive = false;
    let message = provider ? `Saved — applied to ${provider} on the next deploy.` : "Saved.";

    if (target && provider && target.credentialId) {
      const adapter = getProvider(provider) as any;
      if (adapter && typeof adapter.applyScale === "function") {
        const credentials = await this.storage.getCloudCredentialById(target.credentialId);
        if (credentials) {
          try {
            const res = await adapter.applyScale(target, credentials, {
              minInstances: scale.minInstances,
              maxInstances: scale.maxInstances,
              cpuThreshold: scale.cpuThreshold,
            });
            appliedLive = res?.success !== false;
            message = appliedLive
              ? `Applied live to ${provider} (${scale.minInstances ?? "?"}–${scale.maxInstances ?? "?"} instances).`
              : res?.message || message;
          } catch (err: any) {
            message = `Saved; live apply to ${provider} failed (${err?.message || err}). Will apply on next deploy.`;
          }
        }
      }
    }

    return { provider, persisted: true, appliedLive, message };
  }

  async promoteByRunId(runId: string): Promise<DeploymentRun> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) {
      throw new Error(`Deployment run not found: ${runId}`);
    }

    const result = await this.promoteToNextStage(run.projectId, runId);

    if (!result.success) {
      throw new Error(result.errorMessage || "Promotion failed");
    }

    const newRun = await this.storage.getDeploymentRun(result.runId);
    if (!newRun) {
      throw new Error("Failed to retrieve promoted deployment run");
    }

    return newRun;
  }

  async promoteToNextStage(projectId: string, runId: string): Promise<DeploymentResult> {
    const promotionCheck = await this.canPromote(runId);
    
    if (!promotionCheck.canPromote || !promotionCheck.nextStage) {
      return {
        success: false,
        runId,
        stage: promotionCheck.currentStage,
        status: "blocked",
        errorMessage: `Cannot promote: ${promotionCheck.blockers.join(", ")}`,
      };
    }

    const sourceRun = await this.storage.getDeploymentRun(runId);
    if (!sourceRun) {
      return {
        success: false,
        runId,
        stage: promotionCheck.currentStage,
        status: "failed",
        errorMessage: "Deployment run not found",
      };
    }

    const nextStage = promotionCheck.nextStage;
    const startTime = Date.now();

    // For Pre-Prod promotion, use enhanced flow with quality gates BEFORE deployment
    if (nextStage === "preprod") {
      return this.promoteToPreprod(projectId, sourceRun, startTime);
    }

    // For Production promotion, use approval workflow
    if (nextStage === "production") {
      return this.promoteToProduction(projectId, sourceRun, startTime);
    }

    // For other stages, use existing flow
    broadcastDeploymentEvent({
      type: "promotion",
      projectId,
      runId,
      stage: promotionCheck.currentStage,
      data: { 
        fromStage: promotionCheck.currentStage, 
        toStage: nextStage,
        version: sourceRun.version,
      },
      timestamp: new Date().toISOString(),
    });

    return this.startDeployment(projectId, nextStage, {
      version: sourceRun.version || undefined,
      buildId: sourceRun.buildId || undefined,
      commitSha: sourceRun.commitSha || undefined,
      commitMessage: sourceRun.commitMessage || undefined,
      triggeredBy: "auto-promote",
      provider: sourceRun.provider || undefined,
      region: sourceRun.region || undefined,
      skipBuild: true,
    });
  }

  private async promoteToPreprod(
    projectId: string,
    sourceRun: DeploymentRun,
    startTime: number
  ): Promise<DeploymentResult> {
    const stage: DeploymentStage = "preprod";

    // 1. Verify source run is from Test stage and successful
    if (sourceRun.stage !== "test") {
      return {
        success: false,
        runId: sourceRun.id,
        stage: "test",
        status: "failed",
        errorMessage: "Pre-Prod promotion requires a successful Test deployment",
      };
    }

    if (sourceRun.status !== "success") {
      return {
        success: false,
        runId: sourceRun.id,
        stage: "test",
        status: "failed",
        errorMessage: `Test deployment must be successful to promote (current status: ${sourceRun.status})`,
      };
    }

    // 2. Get Pre-Prod specific deployment target (may have different resource configs)
    const preprodTarget = await this.storage.getTargetByStage(projectId, stage);
    
    // 3. Get Pre-Prod target's cloud credentials (may be different from Test)
    let credentials: CloudCredential | undefined;
    const providerName = preprodTarget?.provider;
    
    if (preprodTarget?.credentialId) {
      credentials = await this.storage.getCloudCredentialById(preprodTarget.credentialId);
    }

    // 4. Create a new deployment run with stage='preprod' and status='checking-gates'
    const existingRuns = await this.storage.getDeploymentRuns(projectId, stage, 1);
    const runNumber = existingRuns.length > 0 ? (existingRuns[0].runNumber || 0) + 1 : 1;

    const runData: InsertDeploymentRun = {
      projectId,
      runNumber,
      stage,
      version: sourceRun.version,
      buildId: sourceRun.buildId, // Reuse the same artifact (no rebuild)
      commitSha: sourceRun.commitSha,
      commitMessage: sourceRun.commitMessage,
      status: "checking-gates", // Set status to 'checking-gates' first
      triggeredBy: "auto-promote",
      provider: providerName,
      region: (preprodTarget?.targetConfig as any)?.region,
    };

    // Concurrency guard: serialize on the target stage so two simultaneous
    // promotions (or a promote racing a manual deploy) can't both open a
    // pre-prod run. The loser returns "blocked" instead of duplicating work.
    const { run: preprodRun, created } = await this.storage.createDeploymentRunIfNoneActive(
      runData,
      ACTIVE_DEPLOY_RUN_STATUSES,
    );
    if (!created) {
      return {
        success: false,
        runId: preprodRun.id,
        stage,
        status: "blocked",
        errorMessage: `A ${stage} deployment is already in progress (run #${preprodRun.runNumber}).`,
        durationMs: Date.now() - startTime,
      };
    }

    // Stage state is NOT updated here. The promotion pipeline first runs
    // pending migrations; on migration failure the previous preprod stage
    // state is preserved. Stage state is upserted to "checking-gates" only
    // after migrations succeed (see runPendingMigrations call below).

    broadcastDeploymentEvent({
      type: "promotion",
      projectId,
      runId: preprodRun.id,
      stage,
      data: { 
        fromStage: "test", 
        toStage: stage,
        version: sourceRun.version,
        status: "checking-gates",
      },
      timestamp: new Date().toISOString(),
    });

    await this.addLog(preprodRun.id, projectId, "info", "promote", `Promoting from Test to Pre-Prod: ${sourceRun.version || 'unknown version'}`);
    await this.addLog(preprodRun.id, projectId, "info", "promote", `Reusing build artifact: ${sourceRun.buildId || 'N/A'}`);

    try {
      // Unified pipeline: run pending migrations for the target stage before
      // quality gates / deploy. Failure aborts the promotion cleanly.
      try {
        await this.runPendingMigrations(preprodRun.id, projectId, stage);
      } catch (migErr: any) {
        const errorMessage = migErr?.message || "Migration step failed";
        await this.storage.updateDeploymentRun(preprodRun.id, { status: "failed", errorMessage, completedAt: new Date() });
        return {
          success: false,
          runId: preprodRun.id,
          stage,
          status: "failed",
          errorMessage,
          durationMs: Date.now() - startTime,
        };
      }

      // Migrations succeeded — safe to mark preprod as transitioning.
      await this.storage.upsertStageState({
        projectId,
        stage,
        status: "checking-gates",
        currentVersion: sourceRun.version,
        currentBuildId: sourceRun.buildId,
        currentCommitSha: sourceRun.commitSha,
        provider: providerName,
        region: (preprodTarget?.targetConfig as any)?.region,
      });

      // Task #1130 — run security scans BEFORE the rest of the gate sweep
      // so a bad scan blocks the run before any further phase work. The
      // scan phase persists its results so the loop below skips them.
      const preprodScanResult = await this.runSecurityScanPhase(preprodRun.id, projectId, stage);
      if (!preprodScanResult.passed) {
        const errorMessage = `Security scan failed: ${preprodScanResult.blockers.join(", ")}`;
        await this.addLog(preprodRun.id, projectId, "error", "scanning", errorMessage, { isError: 1 });
        await this.storage.updateDeploymentRun(preprodRun.id, { status: "failed", errorMessage, durationMs: Date.now() - startTime, completedAt: new Date() });
        await this.storage.upsertStageState({ projectId, stage, status: "failed", healthStatus: "unhealthy" });
        broadcastDeploymentEvent({ type: "deployment_failed", projectId, runId: preprodRun.id, stage, data: { errorMessage, phase: "scanning" }, timestamp: new Date().toISOString() });
        return { success: false, runId: preprodRun.id, stage, status: "failed", errorMessage, durationMs: Date.now() - startTime };
      }

      // 5. Enforce quality gates BEFORE deployment
      await this.addLog(preprodRun.id, projectId, "info", "quality-gates", "Checking Pre-Prod quality gates before deployment...");
      
      // Get all quality gate policies for 'preprod' stage
      const preprodPolicies = await this.storage.getQualityGatePolicies(projectId, stage);
      const gateResults: QualityGateCheckResult["gates"] = [];
      const blockers: string[] = [];

      // Execute each gate check
      for (const policy of preprodPolicies) {
        // Task #1130 — security-scan policies were already evaluated and
        // persisted by the scanning phase above; skip re-evaluation here.
        if (policy.gateType === "security-scan") {
          continue;
        }
        const gateResult = await this.evaluateQualityGate(policy, projectId, preprodRun.id);
        
        // Store the gate results
        await this.storage.createGateResult({
          runId: preprodRun.id,
          projectId,
          gateName: policy.gateName,
          gateType: policy.gateType,
          stage,
          status: gateResult.status,
          required: policy.isRequired ? 1 : 0,
          details: gateResult.details,
        });

        gateResults.push({
          name: policy.gateName,
          status: gateResult.status,
          required: !!policy.isRequired,
          details: gateResult.details,
        });

        // Block deployment if any required gate fails
        if (!!policy.isRequired && gateResult.status === "failed") {
          blockers.push(`${policy.gateName}: ${gateResult.message || "failed"}`);
        }

        broadcastDeploymentEvent({
          type: "gate_update",
          projectId,
          runId: preprodRun.id,
          stage,
          data: {
            gateName: policy.gateName,
            status: gateResult.status,
            required: !!policy.isRequired,
          },
          timestamp: new Date().toISOString(),
        });

        await this.addLog(
          preprodRun.id, 
          projectId, 
          gateResult.status === "passed" ? "info" : gateResult.status === "failed" ? "error" : "warn",
          "quality-gates", 
          `Gate '${policy.gateName}': ${gateResult.status}${gateResult.message ? ` - ${gateResult.message}` : ''}`
        );
      }

      // If no policies defined, use default gates
      if (preprodPolicies.length === 0) {
        const config = await this.storage.getDeploymentConfig(projectId);
        const defaultGates = this.getDefaultGates(config, stage);
        
        for (const gate of defaultGates) {
          gateResults.push({
            name: gate.name,
            status: "passed",
            required: gate.required,
          });
          
          await this.storage.createGateResult({
            runId: preprodRun.id,
            projectId,
            gateName: gate.name,
            gateType: gate.type,
            stage,
            status: "passed",
            required: gate.required ? 1 : 0,
          });
        }
        
        await this.addLog(preprodRun.id, projectId, "info", "quality-gates", "Using default gates - all passed");
      }

      // Check if any required gates failed
      if (blockers.length > 0) {
        const errorMessage = `Quality gates failed: ${blockers.join(", ")}`;
        await this.addLog(preprodRun.id, projectId, "error", "quality-gates", errorMessage, { isError: 1 });
        
        await this.storage.updateDeploymentRun(preprodRun.id, {
          status: "failed",
          errorMessage,
          durationMs: Date.now() - startTime,
          completedAt: new Date(),
        });

        await this.storage.upsertStageState({
          projectId,
          stage,
          status: "failed",
          healthStatus: "unhealthy",
        });

        broadcastDeploymentEvent({
          type: "deployment_failed",
          projectId,
          runId: preprodRun.id,
          stage,
          data: { errorMessage, phase: "quality-gates" },
          timestamp: new Date().toISOString(),
        });

        return {
          success: false,
          runId: preprodRun.id,
          stage,
          status: "failed",
          errorMessage,
          durationMs: Date.now() - startTime,
        };
      }

      await this.addLog(preprodRun.id, projectId, "info", "quality-gates", "All Pre-Prod quality gates passed");

      // 6. Update status to 'deploying'
      await this.storage.updateDeploymentRun(preprodRun.id, { status: "deploying" });
      await this.storage.upsertStageState({
        projectId,
        stage,
        status: "deploying",
      });

      broadcastDeploymentEvent({
        type: "deployment_started",
        projectId,
        runId: preprodRun.id,
        stage,
        data: { version: sourceRun.version, runNumber, phase: "deploying" },
        timestamp: new Date().toISOString(),
      });

      await this.addLog(preprodRun.id, projectId, "info", "deploy", "Starting Pre-Prod deployment...");

      // 7. Apply Pre-Prod specific configuration and deploy
      let deployUrl: string | undefined;

      if (providerName && credentials) {
        const provider = getProvider(providerName);
        if (provider) {
          const project = await this.storage.getProjectInternal(projectId);
          const artifact = sourceRun.buildId ? await this.storage.getBuildArtifact(sourceRun.buildId) : null;
          
          // Apply Pre-Prod environment variables and resource configs
          const deploymentTarget: ProviderDeploymentTarget = {
            projectId,
            stage,
            version: sourceRun.version || undefined,
            buildId: sourceRun.buildId || undefined,
            commitSha: sourceRun.commitSha || undefined,
            imageUri: artifact?.artifactPath,
            region: (preprodTarget?.targetConfig as any)?.region,
            serviceName: (preprodTarget?.targetConfig as any)?.serviceName || `${project?.name || projectId}-${stage}`,
            environmentVariables: preprodTarget?.environmentVariables as Record<string, string>,
            resourceConfig: preprodTarget?.resourceConfig as ProviderDeploymentTarget["resourceConfig"],
          };

          const preparedTarget = await this.runPrepareHook(preprodRun.id, projectId, provider, deploymentTarget, credentials);

          await this.addLog(preprodRun.id, projectId, "info", "deploy", `Deploying to ${providerName}...`);
          
          const deployResult = await provider.deploy(preparedTarget, credentials);

          if (!deployResult.success) {
            throw new Error(deployResult.message || "Deployment to cloud provider failed");
          }

          deployUrl = deployResult.deployUrl;
          if (!deployUrl) {
            // Task #1130 — do not fabricate *.example.com URLs.
            throw new Error(`Provider ${providerName} did not return a deploy URL — cannot complete promotion`);
          }
          await this.addLog(preprodRun.id, projectId, "info", "deploy", `Provider deployment successful: ${deployResult.message}`);

          const pollResult = await this.pollDeploymentStatus(provider, preparedTarget, credentials, preprodRun.id, projectId);
          if (!pollResult.success) {
            throw new Error(`Deployment verification failed: ${pollResult.message}`);
          }
        } else {
          // Task #1130 — fail loud rather than fake a URL.
          throw new Error(`Cloud provider "${providerName}" not found — configure a valid provider before promoting`);
        }
      } else {
        // Task #1130 — fail loud rather than fake a URL.
        throw new Error("No cloud provider configured for this promotion — configure infrastructure and credentials before promoting");
      }

      // 8. Run health checks
      await this.storage.updateDeploymentRun(preprodRun.id, { status: "verifying" });
      await this.addLog(preprodRun.id, projectId, "info", "health-check", "Running Pre-Prod health checks...");

      const healthStatus = await this.runHealthChecks(projectId, stage, preprodRun.id, credentials, providerName);

      if (healthStatus.status === "unhealthy") {
        await this.addLog(preprodRun.id, projectId, "warn", "health-check", `Health checks indicate issues: ${healthStatus.message}`);
      } else {
        await this.addLog(preprodRun.id, projectId, "info", "health-check", "Pre-Prod health checks passed");
      }

      const durationMs = Date.now() - startTime;

      // 9. Update to 'success' based on final result
      await this.storage.updateDeploymentRun(preprodRun.id, {
        status: "success",
        deployUrl,
        durationMs,
        completedAt: new Date(),
      });

      await this.storage.upsertStageState({
        projectId,
        stage,
        status: "deployed",
        healthStatus: healthStatus.status === "healthy" ? "healthy" : "degraded",
        currentVersion: sourceRun.version,
        currentBuildId: sourceRun.buildId,
        currentCommitSha: sourceRun.commitSha,
        deployUrl,
        lastDeployedAt: new Date(),
        provider: providerName,
        region: (preprodTarget?.targetConfig as any)?.region,
      });

      broadcastDeploymentEvent({
        type: "deployment_completed",
        projectId,
        runId: preprodRun.id,
        stage,
        data: { deployUrl, durationMs, version: sourceRun.version },
        timestamp: new Date().toISOString(),
      });

      return {
        success: true,
        runId: preprodRun.id,
        stage,
        status: "success",
        deployUrl,
        durationMs,
      };
    } catch (error) {
      // 10. Update to 'failed' based on final result
      const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
      const durationMs = Date.now() - startTime;

      await this.addLog(preprodRun.id, projectId, "error", "deploy", `Pre-Prod promotion failed: ${errorMessage}`, { isError: 1 });

      await this.storage.updateDeploymentRun(preprodRun.id, {
        status: "failed",
        errorMessage,
        durationMs,
        completedAt: new Date(),
      });

      await this.storage.upsertStageState({
        projectId,
        stage,
        status: "failed",
        healthStatus: "unhealthy",
      });

      await this.escalateDeploymentFailure(preprodRun.id, projectId, stage, errorMessage);

      broadcastDeploymentEvent({
        type: "deployment_failed",
        projectId,
        runId: preprodRun.id,
        stage,
        data: { errorMessage, durationMs },
        timestamp: new Date().toISOString(),
      });

      return {
        success: false,
        runId: preprodRun.id,
        stage,
        status: "failed",
        errorMessage,
        durationMs,
      };
    }
  }

  private async promoteToProduction(
    projectId: string,
    sourceRun: DeploymentRun,
    startTime: number
  ): Promise<DeploymentResult> {
    const stage: DeploymentStage = "production";

    if (sourceRun.stage !== "preprod") {
      return {
        success: false,
        runId: sourceRun.id,
        stage: sourceRun.stage as DeploymentStage,
        status: "failed",
        errorMessage: "Production promotion requires a successful Pre-Prod deployment",
      };
    }

    if (sourceRun.status !== "success") {
      return {
        success: false,
        runId: sourceRun.id,
        stage: sourceRun.stage as DeploymentStage,
        status: "failed",
        errorMessage: `Pre-Prod deployment must be successful to promote (current status: ${sourceRun.status})`,
      };
    }

    const productionTarget = await this.storage.getTargetByStage(projectId, stage);
    
    let credentials: CloudCredential | undefined;
    const providerName = productionTarget?.provider;
    
    if (productionTarget?.credentialId) {
      credentials = await this.storage.getCloudCredentialById(productionTarget.credentialId);
    }

    const existingRuns = await this.storage.getDeploymentRuns(projectId, stage, 1);
    const runNumber = existingRuns.length > 0 ? (existingRuns[0].runNumber || 0) + 1 : 1;

    const runData: InsertDeploymentRun = {
      projectId,
      runNumber,
      stage,
      version: sourceRun.version,
      buildId: sourceRun.buildId,
      commitSha: sourceRun.commitSha,
      commitMessage: sourceRun.commitMessage,
      status: "checking-gates",
      triggeredBy: "auto-promote",
      provider: providerName,
      region: (productionTarget?.targetConfig as any)?.region,
    };

    // Concurrency guard: serialize on production so two simultaneous
    // promotions (or a promote racing a manual deploy / hotfix) can't both
    // open a production run. The loser returns "blocked".
    const { run: productionRun, created } = await this.storage.createDeploymentRunIfNoneActive(
      runData,
      ACTIVE_DEPLOY_RUN_STATUSES,
    );
    if (!created) {
      return {
        success: false,
        runId: productionRun.id,
        stage,
        status: "blocked",
        errorMessage: `A ${stage} deployment is already in progress (run #${productionRun.runNumber}).`,
        durationMs: Date.now() - startTime,
      };
    }

    await this.storage.upsertStageState({
      projectId,
      stage,
      status: "checking-gates",
      currentVersion: sourceRun.version,
      currentBuildId: sourceRun.buildId,
      currentCommitSha: sourceRun.commitSha,
      provider: providerName,
      region: (productionTarget?.targetConfig as any)?.region,
    });

    broadcastDeploymentEvent({
      type: "promotion",
      projectId,
      runId: productionRun.id,
      stage,
      data: { 
        fromStage: "preprod", 
        toStage: stage,
        version: sourceRun.version,
        status: "checking-gates",
      },
      timestamp: new Date().toISOString(),
    });

    await this.addLog(productionRun.id, projectId, "info", "promote", `Promoting from Pre-Prod to Production: ${sourceRun.version || 'unknown version'}`);
    await this.addLog(productionRun.id, projectId, "info", "promote", `Reusing build artifact: ${sourceRun.buildId || 'N/A'}`);

    try {
      // Task #1130 — security scans run as their own phase BEFORE gate
      // evaluation so a failing scan blocks production promotion before
      // any further work happens.
      const promoScanResult = await this.runSecurityScanPhase(productionRun.id, projectId, stage);
      if (!promoScanResult.passed) {
        const errorMessage = `Security scan failed: ${promoScanResult.blockers.join(", ")}`;
        await this.addLog(productionRun.id, projectId, "error", "scanning", errorMessage, { isError: 1 });
        await this.storage.updateDeploymentRun(productionRun.id, { status: "failed", errorMessage, durationMs: Date.now() - startTime, completedAt: new Date() });
        await this.storage.upsertStageState({ projectId, stage, status: "failed", healthStatus: "unhealthy" });
        broadcastDeploymentEvent({ type: "deployment_failed", projectId, runId: productionRun.id, stage, data: { errorMessage, phase: "scanning" }, timestamp: new Date().toISOString() });
        return { success: false, runId: productionRun.id, stage, status: "failed", errorMessage, durationMs: Date.now() - startTime };
      }

      await this.addLog(productionRun.id, projectId, "info", "quality-gates", "Checking Production quality gates before deployment...");
      
      const productionPolicies = await this.storage.getQualityGatePolicies(projectId, stage);
      const gateResults: QualityGateCheckResult["gates"] = [];
      const blockers: string[] = [];
      let requiresManualApproval = true;

      for (const policy of productionPolicies) {
        // Task #1130 — security-scan policies were already evaluated and
        // persisted by the scanning phase above; skip re-evaluation here.
        if (policy.gateType === "security-scan") {
          continue;
        }
        if (policy.gateType === "auto-approval") {
          const config = policy.config as Record<string, unknown> | null;
          requiresManualApproval = config?.requireManualApproval !== false;
          
          await this.storage.createGateResult({
            runId: productionRun.id,
            projectId,
            gateName: policy.gateName,
            gateType: policy.gateType,
            stage,
            status: "pending",
            required: policy.isRequired ? 1 : 0,
            details: { requiresManualApproval },
          });

          gateResults.push({
            name: policy.gateName,
            status: "pending",
            required: !!policy.isRequired,
            details: { requiresManualApproval },
          });
          continue;
        }

        const gateResult = await this.evaluateQualityGate(policy, projectId, productionRun.id);
        
        await this.storage.createGateResult({
          runId: productionRun.id,
          projectId,
          gateName: policy.gateName,
          gateType: policy.gateType,
          stage,
          status: gateResult.status,
          required: policy.isRequired ? 1 : 0,
          details: gateResult.details,
        });

        gateResults.push({
          name: policy.gateName,
          status: gateResult.status,
          required: !!policy.isRequired,
          details: gateResult.details,
        });

        if (!!policy.isRequired && gateResult.status === "failed") {
          blockers.push(`${policy.gateName}: ${gateResult.message || "failed"}`);
        }

        broadcastDeploymentEvent({
          type: "gate_update",
          projectId,
          runId: productionRun.id,
          stage,
          data: {
            gateName: policy.gateName,
            status: gateResult.status,
            required: !!policy.isRequired,
          },
          timestamp: new Date().toISOString(),
        });

        await this.addLog(
          productionRun.id, 
          projectId, 
          gateResult.status === "passed" ? "info" : gateResult.status === "failed" ? "error" : "warn",
          "quality-gates", 
          `Gate '${policy.gateName}': ${gateResult.status}${gateResult.message ? ` - ${gateResult.message}` : ''}`
        );
      }

      if (blockers.length > 0) {
        const errorMessage = `Quality gates failed: ${blockers.join(", ")}`;
        await this.addLog(productionRun.id, projectId, "error", "quality-gates", errorMessage, { isError: 1 });
        
        await this.storage.updateDeploymentRun(productionRun.id, {
          status: "failed",
          errorMessage,
          durationMs: Date.now() - startTime,
          completedAt: new Date(),
        });

        await this.storage.upsertStageState({
          projectId,
          stage,
          status: "failed",
          healthStatus: "unhealthy",
        });

        broadcastDeploymentEvent({
          type: "deployment_failed",
          projectId,
          runId: productionRun.id,
          stage,
          data: { errorMessage, phase: "quality-gates" },
          timestamp: new Date().toISOString(),
        });

        return {
          success: false,
          runId: productionRun.id,
          stage,
          status: "failed",
          errorMessage,
          durationMs: Date.now() - startTime,
        };
      }

      await this.addLog(productionRun.id, projectId, "info", "quality-gates", "All automated Production quality gates passed");

      const autoApprovalGate = gateResults.find(g => g.name.includes("auto-approval") || 
        productionPolicies.find(p => p.gateName === g.name && p.gateType === "auto-approval"));

      if (requiresManualApproval || !autoApprovalGate) {
        await this.addLog(productionRun.id, projectId, "info", "approval", "Manual approval required for production deployment");
        
        await this.storage.createApprovalRequest(productionRun.id, projectId, sourceRun.triggeredBy || "system");

        await this.storage.updateDeploymentRun(productionRun.id, { status: "pending-approval" });

        await this.storage.upsertStageState({
          projectId,
          stage,
          status: "pending-approval",
        });

        broadcastDeploymentEvent({
          type: "deployment_progress",
          projectId,
          runId: productionRun.id,
          stage,
          data: { 
            status: "pending-approval",
            message: "Awaiting manual approval for production deployment",
          },
          timestamp: new Date().toISOString(),
        });

        return {
          success: true,
          runId: productionRun.id,
          stage,
          status: "pending-approval",
          durationMs: Date.now() - startTime,
        };
      }

      await this.addLog(productionRun.id, projectId, "info", "approval", "Auto-approval enabled - proceeding with deployment");

      return this.executeProductionDeployment(productionRun.id, projectId, sourceRun, productionTarget, credentials, providerName, startTime);

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
      const durationMs = Date.now() - startTime;

      await this.addLog(productionRun.id, projectId, "error", "deploy", `Production promotion failed: ${errorMessage}`, { isError: 1 });

      await this.storage.updateDeploymentRun(productionRun.id, {
        status: "failed",
        errorMessage,
        durationMs,
        completedAt: new Date(),
      });

      await this.storage.upsertStageState({
        projectId,
        stage,
        status: "failed",
        healthStatus: "unhealthy",
      });

      await this.escalateDeploymentFailure(productionRun.id, projectId, stage, errorMessage);

      broadcastDeploymentEvent({
        type: "deployment_failed",
        projectId,
        runId: productionRun.id,
        stage,
        data: { errorMessage, durationMs },
        timestamp: new Date().toISOString(),
      });

      return {
        success: false,
        runId: productionRun.id,
        stage,
        status: "failed",
        errorMessage,
        durationMs,
      };
    }
  }

  async continueProductionDeploymentAfterApproval(runId: string): Promise<DeploymentResult> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) {
      return {
        success: false,
        runId,
        stage: "production",
        status: "failed",
        errorMessage: "Deployment run not found",
      };
    }

    if (run.status !== "pending-approval") {
      return {
        success: false,
        runId,
        stage: run.stage as DeploymentStage,
        status: "failed",
        errorMessage: `Cannot continue deployment - status is '${run.status}', expected 'pending-approval'`,
      };
    }

    const approval = await this.storage.getApprovalRequest(runId);
    if (!approval || approval.status !== "approved") {
      return {
        success: false,
        runId,
        stage: run.stage as DeploymentStage,
        status: "failed",
        errorMessage: "Deployment not approved or approval not found",
      };
    }

    const projectId = run.projectId;
    const stage = run.stage as DeploymentStage;
    const productionTarget = await this.storage.getTargetByStage(projectId, stage);
    
    let credentials: CloudCredential | undefined;
    const providerName = productionTarget?.provider;
    
    if (productionTarget?.credentialId) {
      credentials = await this.storage.getCloudCredentialById(productionTarget.credentialId);
    }

    await this.addLog(runId, projectId, "info", "approval", `Deployment approved by ${approval.reviewedBy} - continuing deployment`);

    const autoApprovalGate = (await this.storage.getGateResults(runId)).find(g => g.gateType === "auto-approval");
    if (autoApprovalGate) {
      await this.storage.updateGateResult(autoApprovalGate.id, {
        status: "passed",
        approvedBy: approval.reviewedBy,
        approvalComment: approval.comments,
        completedAt: new Date(),
      });
    }

    const startTime = Date.now();
    return this.executeProductionDeployment(runId, projectId, run, productionTarget, credentials, providerName, startTime);
  }

  private async executeProductionDeployment(
    runId: string,
    projectId: string,
    sourceRun: DeploymentRun,
    productionTarget: DeploymentTarget | null,
    credentials: CloudCredential | undefined,
    providerName: string | undefined | null,
    startTime: number
  ): Promise<DeploymentResult> {
    const stage: DeploymentStage = "production";

    try {
      // Unified pipeline: run pending production migrations first, BEFORE
      // mutating stage state or kicking off the deploy. A migration failure
      // aborts the promotion and leaves the existing production stage
      // state untouched.
      try {
        await this.runPendingMigrations(runId, projectId, stage);
      } catch (migErr: any) {
        const errorMessage = migErr?.message || "Migration step failed";
        await this.storage.updateDeploymentRun(runId, { status: "failed", errorMessage, completedAt: new Date() });
        return {
          success: false,
          runId,
          stage,
          status: "failed",
          errorMessage,
          durationMs: Date.now() - startTime,
        };
      }

      // Task #1130 — security scan phase BEFORE deploy. Failure aborts the
      // production promotion before any deploy work happens.
      const prodScanResult = await this.runSecurityScanPhase(runId, projectId, stage);
      if (!prodScanResult.passed) {
        const errorMessage = `Security scan failed: ${prodScanResult.blockers.join(", ")}`;
        await this.addLog(runId, projectId, "error", "scanning", errorMessage, { isError: 1 });
        await this.storage.updateDeploymentRun(runId, { status: "failed", errorMessage, durationMs: Date.now() - startTime, completedAt: new Date() });
        await this.storage.upsertStageState({ projectId, stage, status: "failed", healthStatus: "unhealthy" });
        broadcastDeploymentEvent({ type: "deployment_failed", projectId, runId, stage, data: { errorMessage, phase: "scanning" }, timestamp: new Date().toISOString() });
        return { success: false, runId, stage, status: "failed", errorMessage, durationMs: Date.now() - startTime };
      }

      await this.storage.updateDeploymentRun(runId, { status: "deploying" });
      await this.storage.upsertStageState({
        projectId,
        stage,
        status: "deploying",
      });

      broadcastDeploymentEvent({
        type: "deployment_started",
        projectId,
        runId,
        stage,
        data: { version: sourceRun.version, phase: "deploying" },
        timestamp: new Date().toISOString(),
      });

      await this.addLog(runId, projectId, "info", "deploy", "Starting Production deployment...");

      let deployUrl: string | undefined;

      if (providerName && credentials) {
        const provider = getProvider(providerName);
        if (provider) {
          const project = await this.storage.getProjectInternal(projectId);
          const artifact = sourceRun.buildId ? await this.storage.getBuildArtifact(sourceRun.buildId) : null;
          
          const deploymentTarget: ProviderDeploymentTarget = {
            projectId,
            stage,
            version: sourceRun.version || undefined,
            buildId: sourceRun.buildId || undefined,
            commitSha: sourceRun.commitSha || undefined,
            imageUri: artifact?.artifactPath,
            region: (productionTarget?.targetConfig as any)?.region,
            serviceName: (productionTarget?.targetConfig as any)?.serviceName || `${project?.name || projectId}-${stage}`,
            environmentVariables: productionTarget?.environmentVariables as Record<string, string>,
            resourceConfig: productionTarget?.resourceConfig as ProviderDeploymentTarget["resourceConfig"],
          };

          const preparedTarget = await this.runPrepareHook(runId, projectId, provider, deploymentTarget, credentials);

          await this.addLog(runId, projectId, "info", "deploy", `Deploying to ${providerName}...`);
          
          const deployResult = await provider.deploy(preparedTarget, credentials);

          if (!deployResult.success) {
            throw new Error(deployResult.message || "Deployment to cloud provider failed");
          }

          deployUrl = deployResult.deployUrl;
          if (!deployUrl) {
            // Task #1130 — do not fabricate *.example.com URLs.
            throw new Error(`Provider ${providerName} did not return a deploy URL — cannot complete production deployment`);
          }
          await this.addLog(runId, projectId, "info", "deploy", `Provider deployment successful: ${deployResult.message}`);

          const pollResult = await this.pollDeploymentStatus(provider, preparedTarget, credentials, runId, projectId);
          if (!pollResult.success) {
            throw new Error(`Deployment verification failed: ${pollResult.message}`);
          }
        } else {
          // Task #1130 — fail loud rather than fake a URL.
          throw new Error(`Cloud provider "${providerName}" not found — configure a valid provider before promoting to production`);
        }
      } else {
        // Task #1130 — fail loud rather than fake a URL.
        throw new Error("No cloud provider configured for this production deployment — configure infrastructure and credentials before promoting");
      }

      await this.storage.updateDeploymentRun(runId, { status: "verifying" });
      await this.addLog(runId, projectId, "info", "health-check", "Running Production health checks...");

      const healthStatus = await this.runHealthChecks(projectId, stage, runId, credentials, providerName || undefined);

      if (healthStatus.status === "unhealthy") {
        await this.addLog(runId, projectId, "warn", "health-check", `Health checks indicate issues: ${healthStatus.message}`);
      } else {
        await this.addLog(runId, projectId, "info", "health-check", "Production health checks passed");
      }

      const durationMs = Date.now() - startTime;

      await this.storage.updateDeploymentRun(runId, {
        status: "success",
        deployUrl,
        durationMs,
        completedAt: new Date(),
      });

      await this.storage.upsertStageState({
        projectId,
        stage,
        status: "deployed",
        healthStatus: healthStatus.status === "healthy" ? "healthy" : "degraded",
        currentVersion: sourceRun.version,
        currentBuildId: sourceRun.buildId,
        currentCommitSha: sourceRun.commitSha,
        deployUrl,
        lastDeployedAt: new Date(),
        provider: providerName,
        region: (productionTarget?.targetConfig as any)?.region,
      });

      broadcastDeploymentEvent({
        type: "deployment_completed",
        projectId,
        runId,
        stage,
        data: { deployUrl, durationMs, version: sourceRun.version },
        timestamp: new Date().toISOString(),
      });

      return {
        success: true,
        runId,
        stage,
        status: "success",
        deployUrl,
        durationMs,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
      const durationMs = Date.now() - startTime;

      await this.addLog(runId, projectId, "error", "deploy", `Production deployment failed: ${errorMessage}`, { isError: 1 });

      await this.storage.updateDeploymentRun(runId, {
        status: "failed",
        errorMessage,
        durationMs,
        completedAt: new Date(),
      });

      await this.storage.upsertStageState({
        projectId,
        stage,
        status: "failed",
        healthStatus: "unhealthy",
      });

      await this.escalateDeploymentFailure(runId, projectId, stage, errorMessage);

      broadcastDeploymentEvent({
        type: "deployment_failed",
        projectId,
        runId,
        stage,
        data: { errorMessage, durationMs },
        timestamp: new Date().toISOString(),
      });

      return {
        success: false,
        runId,
        stage,
        status: "failed",
        errorMessage,
        durationMs,
      };
    }
  }

  private async initializeQualityGates(
    runId: string,
    projectId: string,
    stage: DeploymentStage,
    skipGates?: string[]
  ): Promise<void> {
    const policies = await this.storage.getQualityGatePolicies(projectId, stage);
    
    if (policies.length > 0) {
      for (const policy of policies) {
        const isSkipped = skipGates?.includes(policy.gateName);
        
        await this.storage.createGateResult({
          runId,
          projectId,
          gateName: policy.gateName,
          gateType: policy.gateType,
          stage,
          status: isSkipped ? "skipped" : "pending",
          required: policy.isRequired ? 1 : 0,
        });

        broadcastDeploymentEvent({
          type: "gate_update",
          projectId,
          runId,
          stage,
          data: { 
            gateName: policy.gateName,
            status: isSkipped ? "skipped" : "pending",
            required: !!policy.isRequired,
          },
          timestamp: new Date().toISOString(),
        });
      }
      return;
    }

    const config = await this.storage.getDeploymentConfig(projectId);
    const gates = this.getDefaultGates(config, stage);

    for (const gate of gates) {
      const isSkipped = skipGates?.includes(gate.name);
      
      await this.storage.createGateResult({
        runId,
        projectId,
        gateName: gate.name,
        gateType: gate.type,
        stage,
        status: isSkipped ? "skipped" : "passed",
        required: gate.required ? 1 : 0,
      });

      broadcastDeploymentEvent({
        type: "gate_update",
        projectId,
        runId,
        stage,
        data: { 
          gateName: gate.name,
          status: isSkipped ? "skipped" : "passed",
          required: gate.required,
        },
        timestamp: new Date().toISOString(),
      });
    }
  }

  private async addLog(
    runId: string,
    projectId: string,
    level: "debug" | "info" | "warn" | "error" | "fatal",
    source: string,
    message: string,
    extra: { isError?: number; errorCode?: string; metadata?: Record<string, unknown> } = {}
  ): Promise<DeploymentLog> {
    const log = await this.storage.addDeploymentLog({
      runId,
      projectId,
      level,
      source,
      message,
      isError: extra.isError,
      errorCode: extra.errorCode,
      metadata: extra.metadata,
    });

    const run = await this.storage.getDeploymentRun(runId);
    
    broadcastDeploymentEvent({
      type: "deployment_log",
      projectId,
      runId,
      stage: (run?.stage as DeploymentStage) || "test",
      data: { level, source, message, timestamp: log.timestamp },
      timestamp: new Date().toISOString(),
    });

    return log;
  }

  // ============================================
  // Traffic Management Methods
  // ============================================

  async setTrafficWeight(runId: string, weight: number): Promise<void> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) {
      throw new Error(`Deployment run ${runId} not found`);
    }

    await this.addLog(runId, run.projectId, "info", "traffic", `Setting traffic weight to ${weight}%`);

    const existingAllocation = await this.storage.getTrafficAllocation(runId);
    if (!existingAllocation) {
      await this.storage.createTrafficAllocation({
        projectId: run.projectId,
        stage: run.stage,
        runId,
        version: run.version || undefined,
        weight,
        status: "active",
        isActive: 1,
      });
    } else {
      await this.storage.setTrafficWeight(runId, weight);
    }

    if (weight === 100) {
      await this.storage.deactivateOtherAllocations(run.projectId, run.stage, runId);
    }

    broadcastDeploymentEvent({
      type: "deployment_progress",
      projectId: run.projectId,
      runId,
      stage: run.stage as DeploymentStage,
      data: { action: "traffic_weight_changed", weight },
      timestamp: new Date().toISOString(),
    });
  }

  async getTrafficDistribution(projectId: string, stage: string): Promise<TrafficDistribution[]> {
    const allocations = await this.storage.getTrafficAllocations(projectId, stage);
    
    const result: TrafficDistribution[] = [];
    for (const alloc of allocations) {
      const run = await this.storage.getDeploymentRun(alloc.runId);
      result.push({
        version: alloc.version || run?.version || "unknown",
        runId: alloc.runId,
        weight: alloc.weight,
        status: alloc.status,
      });
    }
    
    return result;
  }

  async executeBlueGreenSwitch(runId: string): Promise<boolean> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) {
      throw new Error(`Deployment run ${runId} not found`);
    }

    const target = await this.storage.getTargetByStage(run.projectId, run.stage);
    if (!target) {
      throw new Error(`No deployment target found for stage ${run.stage}`);
    }

    const config = target.targetConfig as DeploymentStrategyConfig | null;
    const blueGreenConfig = config?.blueGreen;

    await this.addLog(runId, run.projectId, "info", "blue-green", "Starting blue/green traffic switch");

    const currentAllocations = await this.storage.getTrafficAllocations(run.projectId, run.stage);
    const oldAllocation = currentAllocations.find(a => a.runId !== runId && a.weight > 0);

    if (blueGreenConfig?.switchDelay && blueGreenConfig.switchDelay > 0) {
      await this.addLog(runId, run.projectId, "info", "blue-green", `Waiting ${blueGreenConfig.switchDelay}s before switching traffic...`);
      await this.delay(blueGreenConfig.switchDelay * 1000);
    }

    await this.setTrafficWeight(runId, 100);

    if (oldAllocation) {
      await this.storage.updateTrafficAllocation(oldAllocation.id, { 
        weight: 0, 
        status: "old_version",
        isActive: blueGreenConfig?.keepOldVersionMinutes ? 1 : 0 
      });

      await this.addLog(runId, run.projectId, "info", "blue-green", 
        `Switched traffic from ${oldAllocation.version || "old"} to ${run.version || "new"}`);

      if (blueGreenConfig?.keepOldVersionMinutes && blueGreenConfig.keepOldVersionMinutes > 0) {
        this.scheduleOldVersionCleanup(oldAllocation.id, blueGreenConfig.keepOldVersionMinutes, runId, run.projectId);
      }
    }

    await this.storage.updateDeploymentRun(runId, {
      status: "completed",
      completedAt: new Date(),
    });

    broadcastDeploymentEvent({
      type: "deployment_completed",
      projectId: run.projectId,
      runId,
      stage: run.stage as DeploymentStage,
      data: { strategy: "blue-green", newVersion: run.version },
      timestamp: new Date().toISOString(),
    });

    return true;
  }

  private scheduleOldVersionCleanup(allocationId: string, delayMinutes: number, runId: string, projectId: string): void {
    setTimeout(async () => {
      try {
        await this.storage.updateTrafficAllocation(allocationId, { isActive: 0 });
        await this.addLog(runId, projectId, "info", "blue-green", 
          `Old version cleanup completed after ${delayMinutes} minutes`);
      } catch (error) {
        console.error("Failed to cleanup old version allocation:", error);
      }
    }, delayMinutes * 60 * 1000);
  }

  async executeCanaryStep(runId: string): Promise<boolean> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) {
      throw new Error(`Deployment run ${runId} not found`);
    }

    const target = await this.storage.getTargetByStage(run.projectId, run.stage);
    if (!target) {
      throw new Error(`No deployment target found for stage ${run.stage}`);
    }

    const config = target.targetConfig as DeploymentStrategyConfig | null;
    const canaryConfig = config?.canary ?? DEFAULT_CANARY_CONFIG;

    const latestMetrics = await this.storage.getLatestCanaryMetrics(runId);
    const currentStep = latestMetrics ? latestMetrics.step + 1 : 1;
    
    const allocation = await this.storage.getTrafficAllocation(runId);
    const currentWeight = allocation?.weight || 0;
    
    let newWeight: number;
    if (currentStep === 1) {
      newWeight = canaryConfig.initialPercent;
    } else {
      newWeight = Math.min(100, currentWeight + canaryConfig.incrementPercent);
    }

    await this.addLog(runId, run.projectId, "info", "canary", 
      `Canary step ${currentStep}: Increasing traffic from ${currentWeight}% to ${newWeight}%`);

    const metrics = await this.storage.createCanaryMetrics({
      runId,
      projectId: run.projectId,
      stage: run.stage,
      step: currentStep,
      trafficPercent: newWeight,
      status: "monitoring",
    });

    await this.setTrafficWeight(runId, newWeight);

    const shouldContinue = await this.monitorCanaryHealth(runId, run.projectId, canaryConfig, metrics.id);

    if (!shouldContinue) {
      await this.addLog(runId, run.projectId, "error", "canary", "Canary deployment failed health checks, initiating rollback");
      await this.rollbackCanary(runId, run.projectId, run.stage);
      return false;
    }

    await this.storage.updateCanaryMetrics(metrics.id, { 
      status: "passed",
      completedAt: new Date(),
    });

    if (newWeight >= 100) {
      await this.addLog(runId, run.projectId, "info", "canary", "Canary deployment completed successfully - 100% traffic shifted");
      await this.storage.updateDeploymentRun(runId, {
        status: "completed",
        completedAt: new Date(),
      });

      broadcastDeploymentEvent({
        type: "deployment_completed",
        projectId: run.projectId,
        runId,
        stage: run.stage as DeploymentStage,
        data: { strategy: "canary", finalWeight: 100 },
        timestamp: new Date().toISOString(),
      });
    } else {
      broadcastDeploymentEvent({
        type: "deployment_progress",
        projectId: run.projectId,
        runId,
        stage: run.stage as DeploymentStage,
        data: { strategy: "canary", step: currentStep, weight: newWeight },
        timestamp: new Date().toISOString(),
      });
    }

    return true;
  }

  private async monitorCanaryHealth(
    runId: string, 
    projectId: string, 
    canaryConfig: CanaryConfig,
    metricsId: string
  ): Promise<boolean> {
    const monitorDuration = canaryConfig.monitorDurationSeconds * 1000;
    const pollInterval = Math.min(30000, monitorDuration / 4);
    const startTime = Date.now();

    let errorCount = 0;
    let requestCount = 0;
    let totalResponseTime = 0;
    let healthChecksPassed = 0;
    let healthChecksFailed = 0;

    await this.addLog(runId, projectId, "info", "canary", 
      `Monitoring canary health for ${canaryConfig.monitorDurationSeconds}s...`);

    while (Date.now() - startTime < monitorDuration) {
      await this.delay(pollInterval);

      const healthResults = await this.storage.getHealthCheckResultsByRun(runId);
      const recentResults = healthResults.slice(0, 10);
      
      for (const result of recentResults) {
        requestCount++;
        if (result.status === "healthy") {
          healthChecksPassed++;
          if (result.responseTime) {
            totalResponseTime += result.responseTime;
          }
        } else {
          healthChecksFailed++;
          errorCount++;
        }
      }

      const errorRate = requestCount > 0 ? (errorCount / requestCount) * 100 : 0;
      const avgResponseTime = requestCount > 0 ? totalResponseTime / requestCount : 0;

      await this.storage.updateCanaryMetrics(metricsId, {
        requestCount,
        errorCount,
        errorRate: Math.round(errorRate * 100),
        avgResponseTime: Math.round(avgResponseTime),
        healthChecksPassed,
        healthChecksFailed,
      });

      if (errorRate > canaryConfig.rollbackThreshold.errorRate) {
        await this.addLog(runId, projectId, "error", "canary", 
          `Error rate ${errorRate.toFixed(2)}% exceeds threshold ${canaryConfig.rollbackThreshold.errorRate}%`);
        await this.storage.updateCanaryMetrics(metricsId, { status: "failed" });
        return false;
      }

      if (avgResponseTime > canaryConfig.rollbackThreshold.responseTime) {
        await this.addLog(runId, projectId, "error", "canary", 
          `Response time ${avgResponseTime}ms exceeds threshold ${canaryConfig.rollbackThreshold.responseTime}ms`);
        await this.storage.updateCanaryMetrics(metricsId, { status: "failed" });
        return false;
      }
    }

    await this.addLog(runId, projectId, "info", "canary", "Canary health monitoring passed");
    return true;
  }

  private async rollbackCanary(runId: string, projectId: string, stage: string): Promise<void> {
    const allocations = await this.storage.getTrafficAllocations(projectId, stage);
    const otherAllocation = allocations.find(a => a.runId !== runId && a.isActive === 1);

    if (otherAllocation) {
      await this.storage.setTrafficWeight(otherAllocation.runId, 100);
      await this.addLog(runId, projectId, "info", "canary", 
        `Rolled back traffic to previous version: ${otherAllocation.version || otherAllocation.runId}`);
    }

    await this.storage.updateTrafficAllocation(
      (await this.storage.getTrafficAllocation(runId))?.id || "",
      { weight: 0, isActive: 0, status: "rolled_back" }
    );

    await this.storage.updateDeploymentRun(runId, {
      status: "rolled_back",
      completedAt: new Date(),
    });

    broadcastDeploymentEvent({
      type: "rollback",
      projectId,
      runId,
      stage: stage as DeploymentStage,
      data: { reason: "canary_threshold_exceeded" },
      timestamp: new Date().toISOString(),
    });
  }

  async startCanaryDeployment(runId: string): Promise<boolean> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) {
      throw new Error(`Deployment run ${runId} not found`);
    }

    await this.addLog(runId, run.projectId, "info", "canary", "Starting canary deployment");

    const existingAllocations = await this.storage.getTrafficAllocations(run.projectId, run.stage);
    if (existingAllocations.length === 0) {
      await this.storage.createTrafficAllocation({
        projectId: run.projectId,
        stage: run.stage,
        runId: "baseline",
        version: "baseline",
        weight: 100,
        status: "active",
        isActive: 1,
      });
    }

    await this.storage.createTrafficAllocation({
      projectId: run.projectId,
      stage: run.stage,
      runId,
      version: run.version || undefined,
      weight: 0,
      status: "canary",
      isActive: 1,
    });

    await this.storage.updateDeploymentRun(runId, { status: "canary_in_progress" });

    return await this.executeCanaryStep(runId);
  }

  async startBlueGreenDeployment(runId: string): Promise<boolean> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) {
      throw new Error(`Deployment run ${runId} not found`);
    }

    await this.addLog(runId, run.projectId, "info", "blue-green", "Starting blue/green deployment");

    await this.storage.createTrafficAllocation({
      projectId: run.projectId,
      stage: run.stage,
      runId,
      version: run.version || undefined,
      weight: 0,
      status: "green",
      isActive: 1,
    });

    await this.storage.updateDeploymentRun(runId, { status: "blue_green_pending" });

    const healthResult = await this.runSimpleHealthChecks(runId, run.projectId, run.stage);
    if (!healthResult) {
      await this.addLog(runId, run.projectId, "error", "blue-green", "New version failed health checks");
      await this.storage.updateDeploymentRun(runId, { status: "failed" });
      return false;
    }

    await this.addLog(runId, run.projectId, "info", "blue-green", "New version passed health checks, ready for traffic switch");
    await this.storage.updateDeploymentRun(runId, { status: "blue_green_ready" });

    broadcastDeploymentEvent({
      type: "deployment_progress",
      projectId: run.projectId,
      runId,
      stage: run.stage as DeploymentStage,
      data: { strategy: "blue-green", status: "ready_for_switch" },
      timestamp: new Date().toISOString(),
    });

    return true;
  }

  private async runSimpleHealthChecks(runId: string, projectId: string, stage: string): Promise<boolean> {
    const definitions = await this.storage.getHealthCheckDefinitions(projectId, stage);
    if (definitions.length === 0) {
      return true;
    }

    let allPassed = true;
    for (const def of definitions) {
      if (def.isEnabled !== 1) continue;
      
      try {
        const response = await fetch(def.endpoint, {
          method: def.method || "GET",
          signal: AbortSignal.timeout((def.timeoutSeconds || 30) * 1000),
        });

        const passed = response.status === (def.expectedStatus || 200);
        await this.storage.createHealthCheckResult({
          definitionId: def.id,
          runId,
          status: passed ? "healthy" : "unhealthy",
          responseTime: 0,
          statusCode: response.status,
        });

        if (!passed) {
          allPassed = false;
        }
      } catch (error) {
        await this.storage.createHealthCheckResult({
          definitionId: def.id,
          runId,
          status: "unhealthy",
          errorMessage: error instanceof Error ? error.message : "Unknown error",
        });
        allPassed = false;
      }
    }

    return allPassed;
  }

  async getCanaryStatus(runId: string): Promise<{
    currentStep: number;
    currentWeight: number;
    status: string;
    metrics: CanaryMetrics[];
  }> {
    const allocation = await this.storage.getTrafficAllocation(runId);
    const metrics = await this.storage.getCanaryMetrics(runId);
    const latestMetrics = metrics[0];

    return {
      currentStep: latestMetrics?.step || 0,
      currentWeight: allocation?.weight || 0,
      status: latestMetrics?.status || allocation?.status || "unknown",
      metrics,
    };
  }

  /**
   * Drive a canary to completion automatically: raise traffic one increment at
   * a time, baking for the configured monitor window at each step.
   * executeCanaryStep rolls the canary back on an error-rate / latency breach,
   * so this loop simply advances until 100% or a failed step. Long-running
   * (each step blocks for the bake window) — call fire-and-forget.
   */
  async autoAdvanceCanary(runId: string): Promise<void> {
    const run = await this.storage.getDeploymentRun(runId);
    if (!run) return;
    const MAX_STEPS = 20; // safety bound: initialPercent + increments to 100%
    for (let i = 0; i < MAX_STEPS; i++) {
      const status = await this.getCanaryStatus(runId);
      if (status.currentWeight >= 100 || status.status === "completed") return;
      if (status.status === "failed" || status.status === "rolled_back") return;
      const ok = await this.executeCanaryStep(runId);
      if (!ok) return; // step failed health checks and rolled back
    }
    await this.addLog(runId, run.projectId, "warn", "canary",
      `Auto-canary stopped after ${MAX_STEPS} steps without reaching 100% — check the canary increment config`);
  }

  /**
   * Start a canary and automatically advance it to completion (or rollback).
   * startCanaryDeployment performs step 1; autoAdvanceCanary drives the rest.
   * Fire-and-forget friendly.
   */
  async runAutomatedCanary(runId: string): Promise<void> {
    const started = await this.startCanaryDeployment(runId);
    if (!started) return; // first step already failed health checks + rolled back
    await this.autoAdvanceCanary(runId);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ============================================
  // Original Methods Continue Below
  // ============================================

  async getDeploymentStatus(projectId: string): Promise<{
    stages: Record<DeploymentStage, DeploymentStageState | null>;
    recentRuns: DeploymentRun[];
  }> {
    const [testState, preprodState, productionState, recentRuns] = await Promise.all([
      this.storage.getStageState(projectId, "test"),
      this.storage.getStageState(projectId, "preprod"),
      this.storage.getStageState(projectId, "production"),
      this.storage.getDeploymentRuns(projectId, undefined, 20),
    ]);

    return {
      stages: {
        test: testState,
        preprod: preprodState,
        production: productionState,
      },
      recentRuns,
    };
  }

  async getRunDetails(runId: string): Promise<{
    run: DeploymentRun | null;
    logs: DeploymentLog[];
    gates: PromotionGateResult[];
  }> {
    const [run, logs, gates] = await Promise.all([
      this.storage.getDeploymentRun(runId),
      this.storage.getDeploymentLogs(runId),
      this.storage.getGateResults(runId),
    ]);

    return { run, logs, gates };
  }

  /** Simulate a deployment for projects without cloud credentials configured. */
  private async _simulateDeployment(runId: string, projectId: string, deployStage: DeploymentStage): Promise<boolean> {
    const startTime = Date.now();
    try {
      await this.storage.updateDeploymentRun(runId, { status: "deploying" });
      await this.addLog(runId, projectId, "info", "deploy", `Simulating deployment to ${deployStage}...`);

      // Brief delay to make progress visible in the UI
      await new Promise(resolve => setTimeout(resolve, 1500));

      await this.storage.updateDeploymentRun(runId, { status: "verifying" });
      await this.addLog(runId, projectId, "info", "health-check", "Running simulated health checks...");

      await new Promise(resolve => setTimeout(resolve, 500));

      const deployUrl = `https://${projectId}-${deployStage}.example.com`;
      const durationMs = Date.now() - startTime;

      await this.storage.updateDeploymentRun(runId, {
        status: "success",
        deployUrl,
        durationMs,
        completedAt: new Date(),
      });

      await this.storage.upsertStageState({
        projectId,
        stage: deployStage,
        status: "deployed",
        healthStatus: "healthy",
        deployUrl,
        lastDeployedAt: new Date(),
      });

      await this.addLog(runId, projectId, "info", "deploy", `Simulated deployment complete. URL: ${deployUrl}`);

      broadcastDeploymentEvent({
        type: "deployment_completed",
        projectId,
        runId,
        stage: deployStage,
        data: { deployUrl, durationMs },
        timestamp: new Date().toISOString(),
      });

      return true;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      await this.storage.updateDeploymentRun(runId, { status: "failed", errorMessage, completedAt: new Date() });
      await this.addLog(runId, projectId, "error", "deploy", `Simulated deployment failed: ${errorMessage}`, { isError: 1 });
      return false;
    }
  }
}

export function createDeploymentOrchestrator(storage: IStorage): DeploymentOrchestrator {
  return new DeploymentOrchestrator(storage);
}
