import { db } from '../db';
import { projects, projectFiles, gitCredentials, organizations, versionCommits, fileSnapshots, branches } from '@shared/schema';
import { eq, and, isNotNull, sql, desc, gt, inArray } from 'drizzle-orm';
import * as fs from 'fs';
import * as path from 'path';
import { createCheckpoint } from './versionControl';
import { GitHubAuthError, GitHubRateLimitError, checkUserRateLimit, updateUserRateLimit, classifyGithubAuthFailure } from './githubApiClient';
import { decryptCredentialField } from './credentialVault';
import { MAX_SYNC_FILE_SIZE, MAX_SYNC_FILE_MB, GITHUB_HARD_LIMIT_BYTES, planPullBatches, PULL_BATCH_MAX_COUNT, PULL_BATCH_MAX_BYTES, isTreeTruncated, TREE_TRUNCATED_MESSAGE } from './gitSyncLimits';
import {
  buildLfsPointer,
  buildLfsContentMarker,
  parseLfsContentMarker,
  parseLfsPointer,
  isLfsContentMarker,
  sha256Hex,
  uploadLfsObject,
  downloadLfsObject,
  storeLfsBlob,
  mergeGitAttributes,
  LFS_CONTENT_PREFIX,
} from './gitLfs';

import { logger } from "../logger";
import { mergePushChanges } from './githubSyncPushMerge';
import { pickWinningSnapshots, chunk, COMMITTED_CONTENT_BATCH_SIZE } from './committedChangesPlanner';

const PROJECT_ROOT = process.cwd();
const BINARY_CONTENT_PREFIX = 'BINARY_BASE64:';

const GITHUB_FETCH_MAX_RETRIES = 2;

/**
 * Auth context passed to {@link githubFetch} so a 401 can be transparently
 * recovered by refreshing the user's OAuth token (Task #1464). When the
 * credential is OAuth-with-refresh-token, the fetch retries once with the
 * refreshed bearer; if the second attempt is still 401, a typed
 * {@link GitHubAuthError} (`code: 'oauth_refresh_failed'` etc.) is thrown.
 */
export interface GithubAuthContext {
  userId: string;
  authMethod: 'oauth' | 'pat' | 'org';
  /** OAuth row id for `connectedServices.id` — surfaced to the client so the
   *  Settings deep-link can pre-target the right account. */
  accountId?: string;
}

export async function githubFetch(
  url: string,
  options: RequestInit,
  userIdOrCtx?: string | GithubAuthContext,
): Promise<Response> {
  const authCtx: GithubAuthContext | undefined =
    typeof userIdOrCtx === 'string'
      ? { userId: userIdOrCtx, authMethod: 'pat' }
      : userIdOrCtx;
  const userId = authCtx?.userId;

  if (userId) {
    const rateCheck = checkUserRateLimit(userId);
    if (!rateCheck.allowed) {
      throw new GitHubRateLimitError(rateCheck.retryAfterMs);
    }
  }

  let didRefresh = false;
  let response: Response | null = null;
  for (let attempt = 0; attempt <= GITHUB_FETCH_MAX_RETRIES; attempt++) {
    response = await fetch(url, options);
    if (userId) {
      updateUserRateLimit(userId, response);
    }

    if (response.status === 401) {
      // Transparent OAuth refresh-on-401: a single retry with a force-refreshed
      // access token. This catches the case where the access token in our DB
      // was still considered "fresh" (hadn't crossed the REFRESH_BUFFER_MS
      // window) but GitHub has already invalidated it.
      if (
        !didRefresh &&
        authCtx?.authMethod === 'oauth' &&
        authCtx.userId
      ) {
        didRefresh = true;
        try {
          const { getFreshGithubTokenDetailed } = await import('./githubOAuth');
          const refreshed = await getFreshGithubTokenDetailed(authCtx.userId, { force: true });
          if (refreshed.refreshFailed || refreshed.noRefreshToken || !refreshed.token) {
            const body: Record<string, unknown> = await response
              .clone()
              .json()
              .catch(() => ({} as Record<string, unknown>));
            const { code, userMessage } = classifyGithubAuthFailure({
              authMethod: 'oauth',
              refreshAttempted: refreshed.refreshFailed,
              hasRefreshToken: !refreshed.noRefreshToken,
              responseBody: body as { message?: string },
            });
            throw new GitHubAuthError(
              'GitHub token is invalid or expired. Please reconnect your GitHub account in Settings.',
              { code, userMessage, authMethod: 'oauth', accountId: authCtx.accountId },
            );
          }
          // Swap the Authorization header in-place and retry once.
          const headers = new Headers(options.headers as HeadersInit | undefined);
          headers.set('Authorization', `Bearer ${refreshed.token}`);
          options.headers = Object.fromEntries(headers.entries());
          continue;
        } catch (err) {
          if (err instanceof GitHubAuthError) throw err;
          log('warn', 'OAuth refresh-on-401 attempt failed', {
            err: err instanceof Error ? err.message : 'unknown',
          });
        }
      }

      const body: Record<string, unknown> = await response
        .clone()
        .json()
        .catch(() => ({} as Record<string, unknown>));
      // If we already attempted a forced refresh in this loop and *still* got
      // a 401, the OAuth credential cannot be salvaged — flag refreshAttempted
      // so the classifier returns `oauth_refresh_failed` instead of falling
      // back to `unknown`.
      const { code, userMessage } = classifyGithubAuthFailure({
        authMethod: authCtx?.authMethod ?? 'pat',
        refreshAttempted: didRefresh,
        responseBody: body as { message?: string },
      });
      throw new GitHubAuthError(
        'GitHub token is invalid or expired. Please reconnect your GitHub account in Settings.',
        { code, userMessage, authMethod: authCtx?.authMethod, accountId: authCtx?.accountId },
      );
    }

    if (response.status === 403) {
      const cloned = response.clone();
      const body: Record<string, unknown> = await cloned.json().catch(() => ({} as Record<string, unknown>));
      const msg = typeof body.message === 'string' ? (body.message as string).toLowerCase() : '';
      const remaining = parseInt(response.headers.get('x-ratelimit-remaining') || '1', 10);
      const isPrimaryRateLimit = remaining === 0;
      const isSecondaryRateLimit = msg.includes('secondary rate limit') || msg.includes('abuse');

      if (isPrimaryRateLimit) {
        const resetEpoch = parseInt(response.headers.get('x-ratelimit-reset') || '0', 10);
        throw new GitHubRateLimitError(Math.max(0, resetEpoch * 1000 - Date.now()));
      }

      if (isSecondaryRateLimit && attempt < GITHUB_FETCH_MAX_RETRIES) {
        const retryAfterHeader = parseInt(response.headers.get('retry-after') || '5', 10);
        const baseMs = Math.max(1000, retryAfterHeader * 1000) * Math.pow(2, attempt);
        const jitterMs = Math.floor(Math.random() * Math.min(2000, baseMs / 2));
        await new Promise(r => setTimeout(r, baseMs + jitterMs));
        continue;
      }
    }

    // Retry transient rate-limit/server errors with exponential backoff + jitter
    if ((response.status === 429 || response.status === 503) && attempt < GITHUB_FETCH_MAX_RETRIES) {
      const retryAfterHeader = parseInt(response.headers.get('retry-after') || '2', 10);
      const baseMs = Math.max(500, retryAfterHeader * 1000) * Math.pow(2, attempt);
      const jitterMs = Math.floor(Math.random() * Math.min(1000, baseMs / 2));
      await new Promise(r => setTimeout(r, baseMs + jitterMs));
      continue;
    }

    return response;
  }
  return response!;
}

const SYNC_LOCK_TTL_MS = 5 * 60 * 1000;

async function ensureSyncLocksTable(): Promise<void> {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS github_sync_locks (
      project_id varchar PRIMARY KEY,
      operation varchar(20) NOT NULL,
      locked_at timestamp NOT NULL DEFAULT now(),
      server_id varchar(100)
    )
  `);
}

let syncLocksTableReady = false;

async function acquireSyncLock(projectId: string, operation: string): Promise<boolean> {
  if (!syncLocksTableReady) {
    await ensureSyncLocksTable();
    syncLocksTableReady = true;
  }

  const ttlCutoff = new Date(Date.now() - SYNC_LOCK_TTL_MS);
  await db.execute(sql`DELETE FROM github_sync_locks WHERE locked_at < ${ttlCutoff}`);

  try {
    await db.execute(sql`
      INSERT INTO github_sync_locks (project_id, operation, locked_at)
      VALUES (${projectId}, ${operation}, now())
    `);
    return true;
  } catch {
    return false;
  }
}

async function releaseSyncLock(projectId: string): Promise<void> {
  try {
    await db.execute(sql`DELETE FROM github_sync_locks WHERE project_id = ${projectId}`);
  } catch {
    console.warn('[GitSync] Failed to release sync lock', projectId);
  }
}

export class SyncLockError extends Error {
  constructor(projectId: string, currentOperation: string) {
    super(`A ${currentOperation} operation is already in progress for this project. Please wait for it to complete.`);
    this.name = 'SyncLockError';
  }
}

// ==========================================
// FILE SIZE AND PATH SECURITY CONSTANTS
// ==========================================

// Maximum file size for sync operations. Single source of truth lives in
// gitSyncLimits.ts (env-configurable via GIT_SYNC_MAX_FILE_MB, default 95MB,
// clamped under GitHub's 100MB hard limit). Task #1964.
const MAX_FILE_SIZE = MAX_SYNC_FILE_SIZE;

// Characters that are dangerous in shell contexts or file paths
// eslint-disable-next-line no-control-regex
const DANGEROUS_PATH_CHARS = /[`$;|&<>\x00]/;

// ==========================================
// PATH VALIDATION
// ==========================================

interface PathValidationResult {
  valid: boolean;
  reason?: string;
}

function validateFilePath(filePath: string, projectRoot?: string): PathValidationResult {
  if (!filePath || typeof filePath !== 'string') {
    return { valid: false, reason: 'File path is empty or invalid' };
  }
  
  // Check for null bytes (path traversal attack vector)
  if (filePath.includes('\0')) {
    return { valid: false, reason: 'File path contains null bytes' };
  }
  
  // Check for path traversal attempts
  if (filePath.includes('..')) {
    return { valid: false, reason: 'File path contains path traversal (..)' };
  }
  
  // NOTE: file paths from git trees are passed to `path.join` and
  // `fs.writeFileSync` — never to a shell — so shell metacharacters like
  // `&`, `;`, `|`, `$`, `(`, `)` are legitimate filename characters and
  // must NOT be rejected (Task #1893). The remaining checks above (null
  // bytes, `..`, and the project-root escape check below) handle the
  // actual filesystem-traversal risks.
  void DANGEROUS_PATH_CHARS;

  
  // If project root is provided, ensure path stays within it
  if (projectRoot) {
    const resolvedPath = path.resolve(projectRoot, filePath);
    const normalizedRoot = path.resolve(projectRoot);
    
    if (!resolvedPath.startsWith(normalizedRoot + path.sep) && resolvedPath !== normalizedRoot) {
      return { valid: false, reason: 'File path escapes project directory' };
    }
  }
  
  return { valid: true };
}

function log(level: 'info' | 'warn' | 'error', message: string, data?: Record<string, any>) {
  const timestamp = new Date().toISOString();
  const prefix = `[GitHubSync][${level.toUpperCase()}]`;
  const dataStr = data ? ` ${JSON.stringify(data)}` : '';
  logger.info(`${timestamp} ${prefix} ${message}${dataStr}`);
}

const TEXT_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx', '.json', '.md', '.txt', '.html', '.css', '.scss',
  '.less', '.yaml', '.yml', '.xml', '.svg', '.py', '.rb', '.go', '.rs', '.java',
  '.c', '.cpp', '.h', '.hpp', '.sh', '.bash', '.zsh', '.gitignore', '.env.example',
  '.eslintrc', '.prettierrc', '.editorconfig', 'Dockerfile', 'Makefile', '.sql',
  '.graphql', '.prisma', '.toml', '.ini', '.cfg', '.conf', '.lock', '.vue', '.svelte'
];

function isTextFile(fileName: string): boolean {
  const lowerName = fileName.toLowerCase();
  return TEXT_EXTENSIONS.some(ext => lowerName.endsWith(ext)) || 
         (!fileName.includes('.') && !lowerName.startsWith('.'));
}

/**
 * Detect a Git LFS pointer in fetched remote content (Task #1967). Pointer
 * blobs are tiny, so they arrive as either plain UTF-8 text or — when the
 * file's extension looks binary — as a `BINARY_BASE64:` payload. Decode both
 * shapes and parse. Returns null for ordinary (non-pointer) content.
 */
function detectLfsPointer(content: string | null): { oid: string; size: number } | null {
  if (content === null) return null;
  let text = content;
  if (content.startsWith(BINARY_CONTENT_PREFIX)) {
    const b64 = content.slice(BINARY_CONTENT_PREFIX.length);
    // A pointer is ~130 bytes; bail early on anything clearly too large to be
    // one so we never base64-decode a real (mistakenly small) binary blob.
    if (b64.length > 4096) return null;
    try {
      text = Buffer.from(b64, 'base64').toString('utf-8');
    } catch {
      return null;
    }
  }
  return parseLfsPointer(text);
}

export interface GitHubSyncStatus {
  isLinked: boolean;
  repoFullName: string | null;
  repoUrl: string | null;
  defaultBranch: string | null;
  lastSynced: string | null;
  /** The exact commit SHA we last synced (pulled/pushed) to, if known. */
  syncedSha: string | null;
  ahead: number;
  behind: number;
  hasLocalChanges: boolean;
}

export interface FileChange {
  path: string;
  status: 'added' | 'modified' | 'deleted';
  size?: number;
  isBinary?: boolean;
  /** Over GitHub's 100MB blob limit — synced via Git LFS (Task #1967). */
  isLfs?: boolean;
}

export interface SyncResult {
  success: boolean;
  message: string;
  filesAffected: number;
  errors: string[];
  /** The provider commit SHA created by a push (absent for pull/no-op). */
  commitSha?: string;
}

export interface BranchInfo {
  name: string;
  sha: string;
  isDefault: boolean;
  isCurrent: boolean;
}

// Get GitHub token for the project owner with org-level fallback
// Priority: 1) User's personal gitCredentials token  2) Organization-level shared token
// Tokens are decrypted transparently if stored encrypted
async function getGitHubToken(projectOwnerId: string | null | undefined): Promise<string | null> {
  const ctx = await getGitHubAuthContext(projectOwnerId);
  return ctx?.token ?? null;
}

/**
 * Resolve the GitHub auth context for a project owner: returns the bearer
 * token plus the metadata needed by {@link githubFetch} to (a) attempt a
 * transparent refresh on 401 and (b) classify the resulting auth failure with
 * a typed `code` + `userMessage` for the client (Task #1464).
 */
export interface GitHubResolvedAuth {
  token: string;
  ctx: GithubAuthContext;
}
export async function getGitHubAuthContext(
  projectOwnerId: string | null | undefined,
): Promise<GitHubResolvedAuth | null> {
  if (!projectOwnerId) {
    log('warn', 'getGitHubAuthContext called without project owner ID - cannot retrieve token securely');
    return null;
  }

  const [credential] = await db.select()
    .from(gitCredentials)
    .where(and(
      eq(gitCredentials.provider, 'github'),
      eq(gitCredentials.userId, projectOwnerId)
    ))
    .limit(1);

  // OAuth path — token lives in connected_services and is refreshed transparently.
  if (credential?.authMethod === 'oauth') {
    try {
      const { getFreshGithubToken } = await import('./githubOAuth');
      const oauthToken = await getFreshGithubToken(projectOwnerId);
      if (oauthToken) {
        const accountId = await loadOauthAccountId(projectOwnerId);
        return {
          token: oauthToken,
          ctx: { userId: projectOwnerId, authMethod: 'oauth', accountId },
        };
      }
    } catch (err) {
      log('warn', 'OAuth token refresh failed, falling back', { err: err instanceof Error ? err.message : 'unknown' });
    }
  }

  if (credential?.token) {
    let token: string;
    try {
      token = decryptCredentialField(credential.token);
    } catch {
      token = credential.token;
    }
    return { token, ctx: { userId: projectOwnerId, authMethod: 'pat' } };
  }

  // 2. Fallback: organization-level shared GitHub token, scoped to the
  // project owner's own organization. We MUST NOT return another tenant's
  // token (cross-tenant credential leakage); look up membership first.
  const { organizationMembers } = await import('@shared/schema');
  const [membership] = await db.select({ orgId: organizationMembers.orgId })
    .from(organizationMembers)
    .where(eq(organizationMembers.id, projectOwnerId))
    .limit(1);

  const ownerOrgId = membership?.orgId;
  if (!ownerOrgId) {
    log('info', 'No GitHub token found for project owner or organization', { ownerId: projectOwnerId });
    return null;
  }

  const [org] = await db.select({ githubToken: organizations.githubToken })
    .from(organizations)
    .where(and(eq(organizations.id, ownerOrgId), isNotNull(organizations.githubToken)))
    .limit(1);

  if (org?.githubToken) {
    log('info', 'Using organization-level GitHub token as fallback', { ownerId: projectOwnerId, orgId: ownerOrgId });
    let token: string;
    try {
      token = decryptCredentialField(org.githubToken);
    } catch {
      token = org.githubToken;
    }
    return { token, ctx: { userId: projectOwnerId, authMethod: 'org' } };
  }

  log('info', 'No GitHub token found for project owner or organization', { ownerId: projectOwnerId });
  return null;
}

async function loadOauthAccountId(userId: string): Promise<string | undefined> {
  try {
    const { connectedServices } = await import('@shared/schema');
    const { isNull } = await import('drizzle-orm');
    const [row] = await db
      .select({ id: connectedServices.id })
      .from(connectedServices)
      .where(
        and(
          eq(connectedServices.userId, userId),
          eq(connectedServices.service, 'github'),
          isNull(connectedServices.deletedAt),
        ),
      )
      .limit(1);
    return row?.id;
  } catch {
    return undefined;
  }
}

async function getProjectWithGitHub(projectId: string) {
  const [project] = await db.select()
    .from(projects)
    .where(eq(projects.id, projectId));
  
  return project;
}

function getProjectPath(projectId: string): string {
  return path.join(PROJECT_ROOT, 'projects', projectId);
}

function getAllFilesRecursively(dirPath: string, basePath: string = ''): { path: string; size: number; isBinary: boolean; isLfs?: boolean }[] {
  const files: { path: string; size: number; isBinary: boolean; isLfs?: boolean }[] = [];
  
  if (!fs.existsSync(dirPath)) {
    return files;
  }
  
  const excludedDirs = ['node_modules', '.git', '.next', 'dist', 'build', '.cache', '__pycache__', '.venv', 'venv'];
  
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  
  for (const entry of entries) {
    const relativePath = basePath ? `${basePath}/${entry.name}` : entry.name;
    const fullPath = path.join(dirPath, entry.name);
    
    // Validate file path for security
    const pathValidation = validateFilePath(relativePath, dirPath.replace(relativePath, ''));
    if (!pathValidation.valid) {
      log('warn', `Skipping file with invalid path: ${relativePath}`, { reason: pathValidation.reason });
      continue;
    }
    
    if (entry.isDirectory()) {
      if (!excludedDirs.includes(entry.name)) {
        files.push(...getAllFilesRecursively(fullPath, relativePath));
      }
    } else {
      const stats = fs.statSync(fullPath);
      
      // Files over the normal sync cap used to be skipped entirely. They are
      // now routed through Git LFS so large binary assets (design videos,
      // etc.) sync instead of being dropped (Task #1967).
      if (stats.size > MAX_FILE_SIZE) {
        files.push({
          path: relativePath,
          size: stats.size,
          isBinary: !isTextFile(entry.name),
          isLfs: true,
        });
        continue;
      }
      
      files.push({ 
        path: relativePath, 
        size: stats.size,
        isBinary: !isTextFile(entry.name)
      });
    }
  }
  
  return files;
}

function readFileContent(filePath: string, isBinary: boolean): string {
  // Check file size before reading
  const stats = fs.statSync(filePath);
  if (stats.size > MAX_FILE_SIZE) {
    log('warn', `Skipping read of large file: ${filePath}`, { 
      size: stats.size, 
      maxSize: MAX_FILE_SIZE,
      sizeMB: (stats.size / (1024 * 1024)).toFixed(2)
    });
    throw new Error(`File exceeds maximum size of ${MAX_FILE_SIZE / (1024 * 1024)}MB: ${filePath}`);
  }
  
  const buffer = fs.readFileSync(filePath);
  if (isBinary) {
    return BINARY_CONTENT_PREFIX + buffer.toString('base64');
  }
  return buffer.toString('utf-8');
}

function writeFileContent(filePath: string, content: string, projectRoot?: string): void {
  // Validate file path before writing
  const relativePath = projectRoot ? path.relative(projectRoot, filePath) : filePath;
  const pathValidation = validateFilePath(relativePath, projectRoot);
  
  if (!pathValidation.valid) {
    log('error', `Refusing to write file with invalid path: ${filePath}`, { reason: pathValidation.reason });
    throw new Error(`Invalid file path: ${pathValidation.reason}`);
  }
  
  if (content.startsWith(BINARY_CONTENT_PREFIX)) {
    const base64 = content.slice(BINARY_CONTENT_PREFIX.length);
    const buffer = Buffer.from(base64, 'base64');
    
    // Check decoded size
    if (buffer.length > MAX_FILE_SIZE) {
      log('warn', `Skipping write of large file: ${filePath}`, { 
        size: buffer.length, 
        maxSize: MAX_FILE_SIZE,
        sizeMB: (buffer.length / (1024 * 1024)).toFixed(2)
      });
      throw new Error(`File content exceeds maximum size of ${MAX_FILE_SIZE / (1024 * 1024)}MB`);
    }
    
    fs.writeFileSync(filePath, buffer);
  } else {
    // Check text content size
    const contentSize = Buffer.byteLength(content, 'utf-8');
    if (contentSize > MAX_FILE_SIZE) {
      log('warn', `Skipping write of large file: ${filePath}`, { 
        size: contentSize, 
        maxSize: MAX_FILE_SIZE,
        sizeMB: (contentSize / (1024 * 1024)).toFixed(2)
      });
      throw new Error(`File content exceeds maximum size of ${MAX_FILE_SIZE / (1024 * 1024)}MB`);
    }
    
    fs.writeFileSync(filePath, content, 'utf-8');
  }
}

/**
 * Cache the remote "behind" count so the panel's frequent status poll (~every
 * 5s per open panel) does not hit the GitHub API on every call. Across many
 * users this keeps GitHub API usage bounded to roughly one request per project
 * per minute instead of one per poll. Task #2007.
 */
const behindCountCache = new Map<string, { count: number; expires: number }>();
const BEHIND_CACHE_TTL_MS = 60 * 1000;

/**
 * Drop any cached behind count for a project. Called right after a successful
 * pull or push so the panel reflects the new sync state immediately instead of
 * showing a stale "behind" number until the cache TTL expires.
 */
function invalidateBehindCache(projectId: string): void {
  const prefix = `${projectId}:`;
  for (const key of Array.from(behindCountCache.keys())) {
    if (key.startsWith(prefix)) behindCountCache.delete(key);
  }
}

/**
 * Count commits on the remote branch that we have not pulled yet. Uses the
 * GitHub commits API filtered to commits authored since our last sync — a real
 * "behind" signal without needing a full local git history. Best-effort: any
 * failure (auth, rate limit, network) returns the last cached value (or 0) so
 * the status poll never fails because of this.
 */
async function getRemoteBehindCount(
  projectId: string,
  project: { githubRepoFullName: string | null; githubDefaultBranch: string | null; githubLastSynced: Date | null; githubLastSyncedSha?: string | null; ownerId: string | null },
): Promise<number> {
  if (!project.githubRepoFullName) return 0;
  const branch = project.githubDefaultBranch || 'main';
  const cacheKey = `${projectId}:${branch}`;
  const cached = behindCountCache.get(cacheKey);
  if (cached && cached.expires > Date.now()) return cached.count;

  try {
    const auth = project.ownerId ? await getGitHubAuthContext(project.ownerId) : null;
    if (!auth) return cached?.count ?? 0;
    const [owner, repo] = project.githubRepoFullName.split('/');
    const headers = {
      'Authorization': `Bearer ${auth.token}`,
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'AgentFactory-App',
    };

    // Preferred path: compare the exact commit we last synced to against the
    // remote branch HEAD. `ahead_by` is the number of commits the remote has
    // that we don't — i.e. how far behind we are. This is reliable even when
    // the remote branch was rebased or force-pushed (timestamps would lie).
    if (project.githubLastSyncedSha) {
      const compareUrl = `https://api.github.com/repos/${owner}/${repo}/compare/${encodeURIComponent(project.githubLastSyncedSha)}...${encodeURIComponent(branch)}`;
      const compareResp = await githubFetch(compareUrl, { headers }, auth.ctx);
      if (compareResp.ok) {
        const compareData = await compareResp.json();
        const count = typeof compareData?.ahead_by === 'number' ? compareData.ahead_by : 0;
        behindCountCache.set(cacheKey, { count, expires: Date.now() + BEHIND_CACHE_TTL_MS });
        return count;
      }
      // A 404 means our stored SHA is no longer reachable from the branch
      // (e.g. history was rewritten and the old commit was garbage-collected).
      // Fall through to the timestamp-based estimate below rather than failing.
    }

    // Fallback (no stored SHA yet, or compare failed): count commits authored
    // since our last sync time. Less reliable, but never breaks the poll.
    let url = `https://api.github.com/repos/${owner}/${repo}/commits?sha=${encodeURIComponent(branch)}&per_page=100`;
    if (project.githubLastSynced) {
      url += `&since=${encodeURIComponent(new Date(project.githubLastSynced).toISOString())}`;
    }
    const resp = await githubFetch(url, { headers }, auth.ctx);
    if (!resp.ok) return cached?.count ?? 0;
    const commits = await resp.json();
    const count = Array.isArray(commits) ? commits.length : 0;
    behindCountCache.set(cacheKey, { count, expires: Date.now() + BEHIND_CACHE_TTL_MS });
    return count;
  } catch (err: unknown) {
    // Never let a behind-count lookup break the status poll.
    const m = err instanceof Error ? err.message : 'unknown';
    log('warn', 'Failed to compute remote behind count', { projectId, error: m });
    return cached?.count ?? 0;
  }
}

export async function getGitHubSyncStatus(projectId: string): Promise<GitHubSyncStatus> {
  const project = await getProjectWithGitHub(projectId);
  
  if (!project || !project.githubRepoFullName) {
    return {
      isLinked: false,
      repoFullName: null,
      repoUrl: null,
      defaultBranch: null,
      lastSynced: null,
      syncedSha: null,
      ahead: 0,
      behind: 0,
      hasLocalChanges: false
    };
  }
  
  const changes = await getLocalChanges(projectId);
  
  let commitsAhead: number;
  try {
    const lastSyncedAt = project.githubLastSynced || new Date(0);
    const { versionCommits, branches: branchesTable } = await import('@shared/schema');
    const { gt, and: andOp, eq: eqOp, count } = await import('drizzle-orm');
    const defaultBranch = await db
      .select({ id: branchesTable.id })
      .from(branchesTable)
      .where(andOp(
        eqOp(branchesTable.projectId, projectId),
        eqOp(branchesTable.isDefault, 1)
      ))
      .limit(1);
    const branchId = defaultBranch[0]?.id;
    const conditions = [
      eqOp(versionCommits.projectId, projectId),
      gt(versionCommits.createdAt, lastSyncedAt)
    ];
    if (branchId) {
      conditions.push(eqOp(versionCommits.branchId, branchId));
    }
    const [result] = await db
      .select({ count: count() })
      .from(versionCommits)
      .where(andOp(...conditions));
    commitsAhead = result?.count ?? 0;
  } catch {
    commitsAhead = changes.length > 0 ? 1 : 0;
  }
  
  const commitsBehind = await getRemoteBehindCount(projectId, project);

  return {
    isLinked: true,
    repoFullName: project.githubRepoFullName,
    repoUrl: project.githubRepoUrl,
    defaultBranch: project.githubDefaultBranch || 'main',
    lastSynced: project.githubLastSynced?.toISOString() || null,
    syncedSha: project.githubLastSyncedSha || null,
    ahead: commitsAhead,
    behind: commitsBehind,
    hasLocalChanges: changes.length > 0
  };
}

export async function getPushedCommitIds(projectId: string): Promise<Set<string>> {
  const project = await getProjectWithGitHub(projectId);
  if (!project || !project.githubLastSynced) return new Set();

  const lastSyncedAt = project.githubLastSynced;

  const defaultBranchRow = await db
    .select({ id: branches.id })
    .from(branches)
    .where(and(eq(branches.projectId, projectId), eq(branches.isDefault, 1)))
    .limit(1);
  const branchId = defaultBranchRow[0]?.id;

  const conditions = [
    eq(versionCommits.projectId, projectId),
    sql`${versionCommits.createdAt} <= ${lastSyncedAt}`
  ];
  if (branchId) {
    conditions.push(eq(versionCommits.branchId, branchId));
  }

  const pushed = await db
    .select({ id: versionCommits.id })
    .from(versionCommits)
    .where(and(...conditions));

  return new Set(pushed.map(c => c.id));
}

export async function getLocalChanges(projectId: string): Promise<FileChange[]> {
  const project = await getProjectWithGitHub(projectId);
  if (!project) {
    return [];
  }
  
  const changes: FileChange[] = [];
  const projectPath = getProjectPath(projectId);
  
  const dbFiles = await db.select()
    .from(projectFiles)
    .where(eq(projectFiles.projectId, projectId));
  
  const dbFileMap = new Map(dbFiles.filter(f => !f.isDirectory).map(f => [f.filePath, f]));
  const localFiles = getAllFilesRecursively(projectPath);
  const localFileSet = new Set(localFiles.map(f => f.path));
  
  for (const localFile of localFiles) {
    const dbFile = dbFileMap.get(localFile.path);

    // LFS files are too large to read into memory for a content diff. Compare
    // the stored byte size instead (the DB row only holds a pointer marker),
    // which is cheap and avoids reading 100MB+ assets on every status check.
    if (localFile.isLfs) {
      if (!dbFile) {
        changes.push({ path: localFile.path, status: 'added', size: localFile.size, isBinary: localFile.isBinary, isLfs: true });
      } else if (!isLfsContentMarker(dbFile.content) || (dbFile.size ?? 0) !== localFile.size) {
        changes.push({ path: localFile.path, status: 'modified', size: localFile.size, isBinary: localFile.isBinary, isLfs: true });
      }
      continue;
    }

    if (!dbFile) {
      changes.push({ path: localFile.path, status: 'added', size: localFile.size, isBinary: localFile.isBinary });
    } else {
      try {
        const localContent = readFileContent(path.join(projectPath, localFile.path), localFile.isBinary);
        if (localContent !== dbFile.content) {
          changes.push({ path: localFile.path, status: 'modified', size: localFile.size, isBinary: localFile.isBinary });
        }
      } catch {
        changes.push({ path: localFile.path, status: 'modified', size: localFile.size, isBinary: localFile.isBinary });
      }
    }
  }
  
  for (const [filePath, dbFile] of Array.from(dbFileMap.entries())) {
    if (localFileSet.has(filePath)) {
      continue;
    }

    // Empty / null-content tracked files must NOT surface as "deleted". This is
    // the documented phantom-delete case: placeholder files (classically
    // .gitkeep) and rows stored without content would otherwise show up as
    // deletions the user never made, because an empty file is frequently not
    // materialised on disk. We defend on two fronts — the pull writes empty
    // blobs to disk so freshly-pulled placeholders really exist, AND here we
    // refuse to emit a deletion for a tracked file that has no content to
    // delete (this also covers existing data that pre-dates the pull fix).
    // Trade-off: a genuine removal of an *empty* file cannot be pushed from this
    // panel — an acceptable price for eliminating .gitkeep noise. LFS pointer
    // markers are non-empty strings, so genuine LFS deletions still report.
    if (dbFile.content == null || dbFile.content === '') {
      continue;
    }

    changes.push({ path: filePath, status: 'deleted' });
  }
  
  return changes;
}

interface CommittedFileChange {
  path: string;
  status: 'added' | 'modified' | 'deleted';
  content?: string;
  isBinary?: boolean;
  isLfs?: boolean;
}

export async function getCommittedChanges(projectId: string, commitIds?: string[]): Promise<CommittedFileChange[]> {
  const project = await getProjectWithGitHub(projectId);
  if (!project) return [];

  // 1. Resolve the set of commit ids whose snapshots we consider.
  let commitIdList: string[];
  if (commitIds && commitIds.length > 0) {
    commitIdList = commitIds;
  } else {
    const lastSynced = project.githubLastSynced;
    const defaultBranchRow = await db
      .select({ id: branches.id })
      .from(branches)
      .where(and(eq(branches.projectId, projectId), eq(branches.isDefault, 1)))
      .limit(1);
    const activeBranchId = defaultBranchRow[0]?.id;
    const commitConditions = [eq(versionCommits.projectId, projectId)];
    if (lastSynced) {
      commitConditions.push(gt(versionCommits.createdAt, lastSynced));
    }
    if (activeBranchId) {
      commitConditions.push(eq(versionCommits.branchId, activeBranchId));
    }
    const commits = await db
      .select({ id: versionCommits.id })
      .from(versionCommits)
      .where(and(...commitConditions))
      .orderBy(desc(versionCommits.createdAt));

    if (commits.length === 0) return [];
    commitIdList = commits.map(c => c.id);
  }
  if (commitIdList.length === 0) return [];

  const inCommitIds = sql`${fileSnapshots.commitId} IN (${sql.join(commitIdList.map(id => sql`${id}`), sql`, `)})`;

  // 2. Metadata-only pass (NO content), newest first — small even for a large
  //    history. Lets us pick the latest snapshot per path before fetching any
  //    file content, instead of loading every historical version's content
  //    into memory at once (the old first-push OOM/timeout risk).
  const meta = await db
    .select({
      id: fileSnapshots.id,
      filePath: fileSnapshots.filePath,
      changeType: fileSnapshots.changeType,
    })
    .from(fileSnapshots)
    .where(and(eq(fileSnapshots.projectId, projectId), inCommitIds))
    .orderBy(desc(fileSnapshots.createdAt));

  // 3. Winning (latest) snapshot per path — same dedup as before, on metadata.
  const winners = pickWinningSnapshots(meta);
  if (winners.length === 0) return [];

  // 4. Fetch content for ONLY the winners, in bounded batches, so peak memory
  //    is one batch of content rather than the whole project's committed file
  //    content at once.
  const contentById = new Map<string, string | null>();
  for (const idBatch of chunk(winners.map(w => w.id), COMMITTED_CONTENT_BATCH_SIZE)) {
    if (idBatch.length === 0) continue;
    const rows = await db
      .select({ id: fileSnapshots.id, contentAfter: fileSnapshots.contentAfter })
      .from(fileSnapshots)
      .where(sql`${fileSnapshots.id} IN (${sql.join(idBatch.map(id => sql`${id}`), sql`, `)})`);
    for (const r of rows) contentById.set(r.id, r.contentAfter);
  }

  // 5. Build the change list in winner order (the newest-first dedup order).
  return winners.map(w => {
    const contentAfter = contentById.get(w.id) ?? null;
    const isLfs = contentAfter?.startsWith(LFS_CONTENT_PREFIX) ?? false;
    const isBinary = !isLfs && (contentAfter?.startsWith(BINARY_CONTENT_PREFIX) ?? false);
    const status: CommittedFileChange['status'] =
      w.changeType === 'created' ? 'added' : w.changeType === 'deleted' ? 'deleted' : 'modified';
    return {
      path: w.filePath,
      status,
      content: contentAfter ?? undefined,
      isBinary,
      isLfs,
    };
  });
}

export async function getBranches(projectId: string): Promise<BranchInfo[]> {
  const project = await getProjectWithGitHub(projectId);
  if (!project?.githubRepoFullName) {
    return [];
  }
  
  const auth = await getGitHubAuthContext(project.ownerId);
  if (!auth) {
    return [];
  }

  const [owner, repo] = project.githubRepoFullName.split('/');

  try {
    const response = await githubFetch(`https://api.github.com/repos/${owner}/${repo}/branches`, {
      headers: {
        'Authorization': `Bearer ${auth.token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'AgentFactory-App'
      }
    }, auth.ctx);

    if (!response.ok) {
      log('warn', 'Failed to fetch branches', { status: response.status });
      return [];
    }

    const branches = await response.json();
    const defaultBranch = project.githubDefaultBranch || 'main';

    return branches.map((b: any) => ({
      name: b.name,
      sha: b.commit.sha,
      isDefault: b.name === defaultBranch,
      isCurrent: b.name === defaultBranch
    }));
  } catch (error) {
    if (error instanceof GitHubAuthError || error instanceof GitHubRateLimitError) throw error;
    log('error', 'Failed to fetch branches', { error: String(error) });
    return [];
  }
}

export interface CreateBranchResult {
  success: boolean;
  message: string;
  branchName?: string;
  sha?: string;
}

export async function createGitHubBranch(projectId: string, branchName: string, fromBranch?: string): Promise<CreateBranchResult> {
  const project = await getProjectWithGitHub(projectId);
  if (!project?.githubRepoFullName) {
    return { success: false, message: 'Project is not linked to a GitHub repository' };
  }

  const auth = await getGitHubAuthContext(project.ownerId);
  if (!auth) {
    return { success: false, message: 'No GitHub token found. Please connect your GitHub account in Settings.' };
  }
  const token = auth.token;

  const [owner, repo] = project.githubRepoFullName.split('/');
  const sourceBranch = fromBranch || project.githubDefaultBranch || 'main';

  try {
    const refResponse = await githubFetch(
      `https://api.github.com/repos/${owner}/${repo}/git/ref/heads/${sourceBranch}`,
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'AgentFactory-App'
        }
      },
      auth.ctx
    );

    if (!refResponse.ok) {
      return { success: false, message: `Source branch '${sourceBranch}' not found on GitHub` };
    }

    const refData = await refResponse.json();
    const sha = refData.object.sha;

    const createResponse = await githubFetch(
      `https://api.github.com/repos/${owner}/${repo}/git/refs`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'AgentFactory-App',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ref: `refs/heads/${branchName}`,
          sha: sha
        })
      },
      project.ownerId ?? undefined
    );

    if (!createResponse.ok) {
      const errorData = await createResponse.json();
      if (createResponse.status === 422) {
        return { success: false, message: `Branch '${branchName}' already exists on GitHub` };
      }
      return { success: false, message: errorData.message || 'Failed to create branch on GitHub' };
    }

    log('info', `Created branch '${branchName}' on GitHub from '${sourceBranch}'`, { projectId, sha });
    return { success: true, message: `Branch '${branchName}' created successfully`, branchName, sha };
  } catch (error) {
    if (error instanceof GitHubAuthError) {
      return { success: false, message: error.message };
    }
    if (error instanceof GitHubRateLimitError) {
      return { success: false, message: 'GitHub rate limit exceeded. Please try again later.' };
    }
    log('error', 'Failed to create branch on GitHub', { error: String(error) });
    return { success: false, message: `Failed to create branch: ${String(error)}` };
  }
}

export async function pullFromGitHub(
  projectId: string,
  branch?: string,
  onProgress?: (processed: number, total: number) => void,
): Promise<SyncResult> {
  const project = await getProjectWithGitHub(projectId);
  if (!project?.githubRepoFullName) {
    return { success: false, message: 'Project is not linked to a GitHub repository', filesAffected: 0, errors: [] };
  }
  
  if (!(await acquireSyncLock(projectId, 'pull'))) {
    return {
      success: false,
      message: 'A sync operation is already in progress for this project. Please wait for it to complete.',
      filesAffected: 0,
      errors: ['SYNC_LOCKED']
    };
  }

  try {
    return await _pullFromGitHubImpl(projectId, project, branch, onProgress);
  } finally {
    await releaseSyncLock(projectId);
  }
}

async function _pullFromGitHubImpl(
  projectId: string,
  project: any,
  branch?: string,
  onProgress?: (processed: number, total: number) => void,
): Promise<SyncResult> {
  // Get GitHub token for the project owner (multi-user safe). Use the rich
  // auth context so githubFetch can transparently refresh OAuth on 401 and
  // surface a typed reconnect error to the route layer (Task #1464).
  const auth = await getGitHubAuthContext(project.ownerId);
  if (!auth) {
    return { success: false, message: 'GitHub is not connected. Please connect your GitHub account.', filesAffected: 0, errors: [] };
  }
  const token = auth.token;
  
  const [owner, repo] = project.githubRepoFullName.split('/');
  const targetBranch = branch || project.githubDefaultBranch || 'main';
  const projectPath = getProjectPath(projectId);
  const errors: string[] = [];
  let filesAffected = 0;
  
  log('info', 'Starting pull from GitHub', { projectId, repo: project.githubRepoFullName, branch: targetBranch });
  
  // Create a backup checkpoint before pulling (allows rollback if pull causes issues)
  try {
    await createCheckpoint(
      projectId,
      `Pre-pull backup from ${project.githubRepoFullName}/${targetBranch}`,
      {
        checkpointType: 'auto',
        includeDbSnapshot: false,
        // Task #1469 — Git sync (pre-pull) checkpoint
        source: 'git_sync',
      }
    );
    log('info', 'Backup checkpoint created before pull');
  } catch (checkpointError: unknown) {
    const cpMsg = checkpointError instanceof Error ? checkpointError.message : 'Unknown error';
    log('warn', 'Failed to create backup checkpoint before pull', { error: cpMsg });
    // Continue with pull even if checkpoint fails
  }
  
  try {
    if (!fs.existsSync(projectPath)) {
      fs.mkdirSync(projectPath, { recursive: true });
    }

    // Load the existing file index once (id keyed by path) instead of doing a
    // full-table select per file. Task #1964.
    const existingByPath = new Map<string, string>();
    {
      const existingRows = await db.select()
        .from(projectFiles)
        .where(eq(projectFiles.projectId, projectId));
      for (const row of existingRows) {
        existingByPath.set(row.filePath, row.id);
      }
    }

    // Memory-safe pull (Task #1964): each remote file is written to disk and
    // upserted to the DB the moment it is fetched, then its content is
    // dropped. We never accumulate the full repo contents in memory, so a
    // repo with many large binaries (videos, etc.) no longer risks OOM.
    // Resolve the branch HEAD commit SHA so we can record exactly which commit
    // this pull synced to. Behind/ahead is then computed by comparing commits
    // (reliable across rebases/force-pushes), not by comparing timestamps.
    // Best-effort: if the ref lookup fails we still pull, we just don't update
    // the stored SHA.
    let syncedHeadSha: string | null = null;
    try {
      const headRefResponse = await githubFetch(`https://api.github.com/repos/${owner}/${repo}/git/ref/heads/${targetBranch}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'AgentFactory-App'
        }
      }, auth.ctx);
      if (headRefResponse.ok) {
        const headRefData = await headRefResponse.json();
        syncedHeadSha = headRefData?.object?.sha ?? null;
      }
    } catch (refErr: unknown) {
      const m = refErr instanceof Error ? refErr.message : 'unknown';
      log('warn', 'Failed to resolve branch HEAD SHA before pull', { projectId, branch: targetBranch, error: m });
    }

    // Fetch the tree/blobs from the exact commit we resolved above (an
    // immutable SHA), not the moving branch ref. Otherwise, if the branch
    // advances between resolving HEAD and fetching the tree, we'd pull one
    // commit's files but record a different commit's SHA — producing a false
    // "behind" count immediately after a successful pull. When the ref lookup
    // failed (syncedHeadSha === null) we fall back to the branch name and also
    // skip persisting the SHA below, so content and stored SHA never diverge.
    const fetchRef = syncedHeadSha || targetBranch;
    let processedCount = 0;
    let totalRemoteFiles = 0;
    await fetchAllRemoteFiles(token, owner, repo, fetchRef, '', auth.ctx, async (file) => {
      try {
        // Validate file path before processing
        const pathValidation = validateFilePath(file.path, projectPath);
        if (!pathValidation.valid) {
          log('warn', `Skipping file with invalid path from remote: ${file.path}`, { reason: pathValidation.reason });
          errors.push(`Invalid path: ${file.path} - ${pathValidation.reason}`);
          return;
        }

        const localPath = path.join(projectPath, file.path);
        const dir = path.dirname(localPath);

        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }

        // Git LFS (Task #1967): the tree blob for a large file is a tiny
        // pointer (~130 bytes), so it sails past the size filter and arrives
        // here as ordinary content. Detect it, fetch the real object through
        // the LFS Batch API into object storage, write the real bytes to disk,
        // and store only the pointer marker in the DB (never the base64 blob).
        const pointer = detectLfsPointer(file.content);
        if (pointer) {
          try {
            const buffer = await downloadLfsObject(owner, repo, token, pointer.oid, pointer.size, targetBranch);
            fs.writeFileSync(localPath, buffer);
            filesAffected++;
          } catch (lfsErr: unknown) {
            const m = lfsErr instanceof Error ? lfsErr.message : 'Unknown error';
            errors.push(`Failed to pull LFS file ${file.path}: ${m}`);
          }

          const lfsMarker = buildLfsContentMarker(pointer.oid, pointer.size);
          const existingLfsId = existingByPath.get(file.path);
          if (existingLfsId) {
            await db.update(projectFiles)
              .set({ content: lfsMarker, sha: file.sha, size: pointer.size })
              .where(eq(projectFiles.id, existingLfsId));
          } else {
            await db.insert(projectFiles).values({
              projectId,
              filePath: file.path,
              fileName: file.name,
              content: lfsMarker,
              size: pointer.size,
              sha: file.sha,
              isDirectory: false
            });
          }
          return;
        }

        if (file.content !== null) {
          writeFileContent(localPath, file.content, projectPath);
          filesAffected++;
        }

        const existingId = existingByPath.get(file.path);
        if (existingId) {
          await db.update(projectFiles)
            .set({ content: file.content, sha: file.sha, size: file.size })
            .where(eq(projectFiles.id, existingId));
        } else {
          await db.insert(projectFiles).values({
            projectId,
            filePath: file.path,
            fileName: file.name,
            content: file.content,
            size: file.size,
            sha: file.sha,
            isDirectory: false
          });
        }
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : 'Unknown error';
        errors.push(`Failed to pull ${file.path}: ${errMsg}`);
      } finally {
        processedCount++;
        onProgress?.(processedCount, totalRemoteFiles);
      }
    }, (total) => { totalRemoteFiles = total; });

    await db.update(projects)
      .set({
        githubLastSynced: new Date(),
        // Always write the resolved commit SHA — including null when the HEAD
        // ref lookup failed. Leaving a previous (now stale) SHA in place would
        // make the behind-count compare against a commit that no longer
        // represents what we just pulled, reporting false "behind" counts. A
        // null SHA correctly falls back to the timestamp-based behind count.
        githubLastSyncedSha: syncedHeadSha,
      })
      .where(eq(projects.id, projectId));
    // The sync state just changed — drop the cached behind count so the panel
    // reflects it immediately instead of showing a stale number for up to a
    // minute (the cache TTL).
    invalidateBehindCache(projectId);
    
    log('info', 'Pull completed', { filesAffected, errors: errors.length, syncedHeadSha });
    
    return {
      success: true,
      message: `Successfully pulled ${filesAffected} files from ${targetBranch}`,
      filesAffected,
      errors
    };
  } catch (error: unknown) {
    if (error instanceof GitHubAuthError || error instanceof GitHubRateLimitError) {
      throw error;
    }
    const errMsg = error instanceof Error ? error.message : 'Pull failed';
    log('error', 'Pull failed', { error: errMsg });
    return { success: false, message: errMsg, filesAffected: 0, errors: [errMsg] };
  }
}

export async function pushToGitHub(
  projectId: string, 
  commitMessage: string, 
  branch?: string,
  filesToPush?: string[],
  commitIds?: string[]
): Promise<SyncResult> {
  const project = await getProjectWithGitHub(projectId);
  if (!project?.githubRepoFullName) {
    return { success: false, message: 'Project is not linked to a GitHub repository', filesAffected: 0, errors: [] };
  }
  
  if (!(await acquireSyncLock(projectId, 'push'))) {
    return {
      success: false,
      message: 'A sync operation is already in progress for this project. Please wait for it to complete.',
      filesAffected: 0,
      errors: ['SYNC_LOCKED']
    };
  }

  try {
    return await _pushToGitHubImpl(projectId, project, commitMessage, branch, filesToPush, commitIds);
  } finally {
    await releaseSyncLock(projectId);
  }
}

/**
 * Create (or move) a lightweight git tag on the linked GitHub repo pointing at
 * the current head of `branch` — i.e. the just-deployed commit. Used to mark
 * deployed releases (e.g. `deploy-production-hotfix-12`) so the remote repo
 * reflects exactly what is live. Best-effort: returns a structured result and
 * never throws, so a tagging hiccup can't fail a successful deployment.
 */
export async function createDeployTag(
  projectId: string,
  tag: string,
  branch?: string,
): Promise<SyncResult> {
  const project = await getProjectWithGitHub(projectId);
  if (!project?.githubRepoFullName) {
    return { success: false, message: 'Project is not linked to a GitHub repository', filesAffected: 0, errors: ['NOT_LINKED'] };
  }
  const auth = await getGitHubAuthContext(project.ownerId);
  if (!auth) {
    return { success: false, message: 'GitHub is not connected', filesAffected: 0, errors: ['NOT_CONNECTED'] };
  }
  const [owner, repo] = project.githubRepoFullName.split('/');
  const targetBranch = branch || project.githubDefaultBranch || 'main';
  const headers = {
    'Authorization': `Bearer ${auth.token}`,
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'AgentFactory-App',
  };
  try {
    const refResponse = await githubFetch(
      `https://api.github.com/repos/${owner}/${repo}/git/ref/heads/${targetBranch}`,
      { headers },
      auth.ctx,
    );
    if (!refResponse.ok) {
      return { success: false, message: `Branch '${targetBranch}' not found on GitHub`, filesAffected: 0, errors: ['BRANCH_NOT_FOUND'] };
    }
    const sha = (await refResponse.json()).object.sha as string;

    const createResponse = await githubFetch(
      `https://api.github.com/repos/${owner}/${repo}/git/refs`,
      {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ref: `refs/tags/${tag}`, sha }),
      },
      auth.ctx,
    );
    if (createResponse.ok) {
      return { success: true, message: `Tagged ${tag} → ${sha.slice(0, 7)}`, filesAffected: 1, errors: [], commitSha: sha };
    }
    // 422 = tag already exists (e.g. an idempotent re-deploy). Move it forward.
    if (createResponse.status === 422) {
      const updateResponse = await githubFetch(
        `https://api.github.com/repos/${owner}/${repo}/git/refs/tags/${tag}`,
        {
          method: 'PATCH',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ sha, force: true }),
        },
        auth.ctx,
      );
      if (updateResponse.ok) {
        return { success: true, message: `Updated tag ${tag} → ${sha.slice(0, 7)}`, filesAffected: 1, errors: [], commitSha: sha };
      }
      return { success: false, message: `Tag '${tag}' exists and could not be updated`, filesAffected: 0, errors: ['TAG_UPDATE_FAILED'] };
    }
    const errBody = await createResponse.text().catch(() => '');
    return { success: false, message: `Failed to create tag '${tag}': ${createResponse.status} ${errBody.slice(0, 200)}`, filesAffected: 0, errors: ['TAG_CREATE_FAILED'] };
  } catch (err: any) {
    return { success: false, message: `Tag creation error: ${err?.message || err}`, filesAffected: 0, errors: ['TAG_EXCEPTION'] };
  }
}

async function _pushToGitHubImpl(
  projectId: string,
  project: { githubRepoFullName: string | null; githubDefaultBranch: string | null; ownerId: string | null },
  commitMessage: string,
  branch?: string,
  filesToPush?: string[],
  commitIds?: string[]
): Promise<SyncResult> {
  const auth = await getGitHubAuthContext(project.ownerId);
  if (!auth) {
    return { success: false, message: 'GitHub is not connected. Please connect your GitHub account.', filesAffected: 0, errors: [] };
  }
  const token = auth.token;

  const [owner, repo] = project.githubRepoFullName!.split('/');
  const targetBranch = branch || project.githubDefaultBranch || 'main';
  const projectPath = getProjectPath(projectId);
  const errors: string[] = [];
  let filesAffected = 0;
  
  log('info', 'Starting push to GitHub', { projectId, repo: project.githubRepoFullName, branch: targetBranch });
  
  try {
    const committedChanges = await getCommittedChanges(projectId, commitIds);
    const workingTreeChanges = await getLocalChanges(projectId);

    // `useCommitted` still gates whether a change's INLINE snapshot content is
    // trusted in the tree builder below (working-tree entries carry no content
    // and fall through to a disk read). The set we push is the UNION of both,
    // so an un-checkpointed on-disk edit is never silently dropped.
    const useCommitted = committedChanges.length > 0;
    const sourceChanges = mergePushChanges(committedChanges, workingTreeChanges);
    const changesToPush = filesToPush
      ? sourceChanges.filter(c => filesToPush.includes(c.path))
      : sourceChanges;
    
    if (changesToPush.length === 0) {
      return { success: true, message: 'No changes to push', filesAffected: 0, errors: [] };
    }
    
    const ownerId = auth.ctx;
    const refResponse = await githubFetch(`https://api.github.com/repos/${owner}/${repo}/git/ref/heads/${targetBranch}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'AgentFactory-App'
      }
    }, ownerId);
    
    if (!refResponse.ok) {
      const errorData = await refResponse.json().catch(() => ({}));
      throw new Error(`Failed to get branch ref: ${refResponse.status} - ${errorData.message || 'Unknown error'}`);
    }
    
    const refData = await refResponse.json();
    const latestCommitSha = refData.object.sha;
    
    const commitResponse = await githubFetch(`https://api.github.com/repos/${owner}/${repo}/git/commits/${latestCommitSha}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'AgentFactory-App'
      }
    }, ownerId);
    
    if (!commitResponse.ok) {
      throw new Error(`Failed to get commit: ${commitResponse.status}`);
    }
    
    const commitData = await commitResponse.json();
    const baseTreeSha = commitData.tree.sha;
    
    const treeItems: any[] = [];
    const pushedFiles: { path: string; content: string; sha: string; size: number; isBinary: boolean }[] = [];
    // Paths pushed through Git LFS this round — used to merge `.gitattributes`
    // so real git clients and GitHub's web UI resolve the pointers (Task #1967).
    const lfsPaths: string[] = [];
    
    for (const change of changesToPush) {
      if (change.status === 'deleted') {
        treeItems.push({
          path: change.path,
          mode: '100644',
          type: 'blob',
          sha: null
        });
        filesAffected++;
      } else {
        const committedChange = change as CommittedFileChange;
        const hasCommittedContent = useCommitted && committedChange.content !== undefined;
        const filePath = path.join(projectPath, change.path);

        // Git LFS path (Task #1967): files over GitHub's blob limit are
        // uploaded as LFS objects and represented in the tree by a small
        // pointer blob. The bytes never sit in the git tree or the DB row.
        const committedIsLfs = hasCommittedContent && isLfsContentMarker(committedChange.content);
        const isLfs = (change as FileChange).isLfs === true || committedIsLfs;
        if (isLfs) {
          try {
            let oid: string;
            let lfsSize: number;
            if (committedIsLfs) {
              const ptr = parseLfsContentMarker(committedChange.content)!;
              oid = ptr.oid;
              lfsSize = ptr.size;
              // Object already uploaded on the push that created the marker.
            } else {
              if (!fs.existsSync(filePath)) {
                errors.push(`Skipped LFS file (missing on disk): ${change.path}`);
                continue;
              }
              const buffer = fs.readFileSync(filePath);
              lfsSize = buffer.length;
              oid = sha256Hex(buffer);
              await uploadLfsObject(owner, repo, token, oid, lfsSize, buffer, targetBranch);
              try {
                await storeLfsBlob(oid, buffer);
              } catch (storeErr: unknown) {
                const m = storeErr instanceof Error ? storeErr.message : 'unknown';
                log('warn', `Failed to cache LFS object in storage: ${change.path}`, { error: m });
              }
            }

            const pointerText = buildLfsPointer(oid, lfsSize);
            const blobResponse = await githubFetch(`https://api.github.com/repos/${owner}/${repo}/git/blobs`, {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'AgentFactory-App',
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ content: pointerText, encoding: 'utf-8' })
            }, ownerId);

            if (!blobResponse.ok) {
              const errorText = await blobResponse.text().catch(() => 'Unknown error');
              errors.push(`Failed to create LFS pointer blob for ${change.path}: ${errorText}`);
              continue;
            }

            const blobData = await blobResponse.json();
            treeItems.push({ path: change.path, mode: '100644', type: 'blob', sha: blobData.sha });
            lfsPaths.push(change.path);
            pushedFiles.push({
              path: change.path,
              content: buildLfsContentMarker(oid, lfsSize),
              sha: blobData.sha,
              size: lfsSize,
              isBinary: true,
            });
            filesAffected++;
          } catch (lfsErr: unknown) {
            const m = lfsErr instanceof Error ? lfsErr.message : 'Unknown error';
            errors.push(`Failed to push LFS file ${change.path}: ${m}`);
          }
          continue;
        }

        if (hasCommittedContent || fs.existsSync(filePath)) {
          const isBinary = change.isBinary ?? !isTextFile(change.path);
          let blobContent: string;
          let encoding: string;
          
          if (hasCommittedContent) {
            const raw = committedChange.content!;
            if (raw.startsWith(BINARY_CONTENT_PREFIX)) {
              blobContent = raw.slice(BINARY_CONTENT_PREFIX.length);
              encoding = 'base64';
            } else {
              blobContent = raw;
              encoding = 'utf-8';
            }
          } else if (isBinary) {
            const buffer = fs.readFileSync(filePath);
            blobContent = buffer.toString('base64');
            encoding = 'base64';
          } else {
            blobContent = fs.readFileSync(filePath, 'utf-8');
            encoding = 'utf-8';
          }
          
          const blobResponse = await githubFetch(`https://api.github.com/repos/${owner}/${repo}/git/blobs`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': 'AgentFactory-App',
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              content: blobContent,
              encoding
            })
          }, ownerId);
          
          if (!blobResponse.ok) {
            const errorText = await blobResponse.text().catch(() => 'Unknown error');
            errors.push(`Failed to create blob for ${change.path}: ${errorText}`);
            continue;
          }
          
          const blobData = await blobResponse.json();
          treeItems.push({
            path: change.path,
            mode: '100644',
            type: 'blob',
            sha: blobData.sha
          });
          
          const storedContent = isBinary 
            ? BINARY_CONTENT_PREFIX + blobContent 
            : blobContent;
          let fileSize: number;
          if (hasCommittedContent) {
            fileSize = Buffer.byteLength(blobContent, encoding === 'base64' ? 'base64' : 'utf-8');
          } else {
            try {
              fileSize = fs.statSync(filePath).size;
            } catch {
              fileSize = Buffer.byteLength(blobContent, encoding === 'base64' ? 'base64' : 'utf-8');
            }
          }
          pushedFiles.push({ path: change.path, content: storedContent, sha: blobData.sha, size: fileSize, isBinary });
          filesAffected++;
        }
      }
    }
    
    // Ensure `.gitattributes` tracks the LFS paths so real git clients and
    // GitHub resolve the pointers as LFS objects (Task #1967).
    if (lfsPaths.length > 0) {
      try {
        const gitAttrPath = path.join(projectPath, '.gitattributes');
        let existingAttrs = '';
        if (fs.existsSync(gitAttrPath)) {
          existingAttrs = fs.readFileSync(gitAttrPath, 'utf-8');
        } else {
          const [dbAttr] = await db.select()
            .from(projectFiles)
            .where(and(eq(projectFiles.projectId, projectId), eq(projectFiles.filePath, '.gitattributes')));
          if (dbAttr?.content && !isLfsContentMarker(dbAttr.content) && !dbAttr.content.startsWith(BINARY_CONTENT_PREFIX)) {
            existingAttrs = dbAttr.content;
          }
        }
        const merged = mergeGitAttributes(existingAttrs, lfsPaths);
        if (merged !== null) {
          const attrBlobResponse = await githubFetch(`https://api.github.com/repos/${owner}/${repo}/git/blobs`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': 'AgentFactory-App',
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ content: merged, encoding: 'utf-8' })
          }, ownerId);
          if (attrBlobResponse.ok) {
            const attrBlob = await attrBlobResponse.json();
            // Replace any existing .gitattributes tree item so we don't push two.
            const idx = treeItems.findIndex(t => t.path === '.gitattributes');
            const attrItem = { path: '.gitattributes', mode: '100644', type: 'blob', sha: attrBlob.sha };
            if (idx >= 0) treeItems[idx] = attrItem; else treeItems.push(attrItem);
            try {
              fs.writeFileSync(gitAttrPath, merged, 'utf-8');
            } catch { /* best-effort working-tree update */ }
            pushedFiles.push({ path: '.gitattributes', content: merged, sha: attrBlob.sha, size: Buffer.byteLength(merged, 'utf-8'), isBinary: false });
          } else {
            const t = await attrBlobResponse.text().catch(() => 'Unknown error');
            log('warn', 'Failed to create .gitattributes blob for LFS tracking', { error: t });
          }
        }
      } catch (attrErr: unknown) {
        const m = attrErr instanceof Error ? attrErr.message : 'Unknown error';
        log('warn', 'Failed to update .gitattributes for LFS tracking', { error: m });
      }
    }

    if (treeItems.length === 0) {
      return { success: false, message: 'No files to push', filesAffected: 0, errors };
    }
    
    const treeResponse = await githubFetch(`https://api.github.com/repos/${owner}/${repo}/git/trees`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'AgentFactory-App',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        base_tree: baseTreeSha,
        tree: treeItems
      })
    }, ownerId);
    
    if (!treeResponse.ok) {
      const errorData = await treeResponse.json().catch(() => ({}));
      throw new Error(`Failed to create tree: ${treeResponse.status} - ${errorData.message || 'Unknown error'}`);
    }
    
    const treeData = await treeResponse.json();
    
    const newCommitResponse = await githubFetch(`https://api.github.com/repos/${owner}/${repo}/git/commits`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'AgentFactory-App',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        message: commitMessage,
        tree: treeData.sha,
        parents: [latestCommitSha]
      })
    }, ownerId);
    
    if (!newCommitResponse.ok) {
      const errorData = await newCommitResponse.json().catch(() => ({}));
      throw new Error(`Failed to create commit: ${newCommitResponse.status} - ${errorData.message || 'Unknown error'}`);
    }
    
    const newCommitData = await newCommitResponse.json();
    
    const updateRefResponse = await githubFetch(`https://api.github.com/repos/${owner}/${repo}/git/refs/heads/${targetBranch}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'AgentFactory-App',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        sha: newCommitData.sha
      })
    }, ownerId);
    
    if (!updateRefResponse.ok) {
      const errorData = await updateRefResponse.json().catch(() => ({}));
      throw new Error(`Failed to update ref: ${updateRefResponse.status} - ${errorData.message || 'Unknown error'}`);
    }
    
    // Build a path→id Map once to avoid N+1 queries in the loops below.
    const pushedFilesByPath = new Map<string, string>();
    {
      const rows = await db.select({ id: projectFiles.id, filePath: projectFiles.filePath })
        .from(projectFiles)
        .where(eq(projectFiles.projectId, projectId));
      for (const row of rows) pushedFilesByPath.set(row.filePath, row.id);
    }

    // Batch DB writes: separate files into inserts vs updates, then issue
    // one INSERT for all new rows, parallel UPDATEs for existing rows, and
    // a single inArray DELETE for removed files.
    const toInsert: typeof pushedFiles = [];
    const toUpdate: { id: string; file: (typeof pushedFiles)[0] }[] = [];
    for (const file of pushedFiles) {
      const existingId = pushedFilesByPath.get(file.path);
      if (existingId) {
        toUpdate.push({ id: existingId, file });
      } else {
        toInsert.push(file);
      }
    }

    // Batch inserts in chunks of 500 to avoid hitting PG parameter limits.
    const INSERT_CHUNK = 500;
    for (let i = 0; i < toInsert.length; i += INSERT_CHUNK) {
      const chunk = toInsert.slice(i, i + INSERT_CHUNK);
      await db.insert(projectFiles).values(chunk.map(f => ({
        projectId,
        filePath: f.path,
        fileName: path.basename(f.path),
        content: f.content,
        sha: f.sha,
        size: f.size,
        isDirectory: false,
      })));
    }

    // Parallel updates — concurrent round-trips instead of sequential.
    await Promise.all(toUpdate.map(({ id, file }) =>
      db.update(projectFiles)
        .set({ content: file.content, sha: file.sha, size: file.size })
        .where(eq(projectFiles.id, id))
    ));

    // Batch deletes with inArray.
    const toDeleteIds = changesToPush
      .filter(c => c.status === 'deleted')
      .map(c => pushedFilesByPath.get(c.path))
      .filter((id): id is string => !!id);
    if (toDeleteIds.length > 0) {
      for (let i = 0; i < toDeleteIds.length; i += INSERT_CHUNK) {
        await db.delete(projectFiles).where(inArray(projectFiles.id, toDeleteIds.slice(i, i + INSERT_CHUNK)));
      }
    }
    
    await db.update(projects)
      .set({
        githubLastSynced: new Date(),
        ...(newCommitData?.sha ? { githubLastSyncedSha: newCommitData.sha } : {}),
      })
      .where(eq(projects.id, projectId));
    // The sync state just changed — drop the cached behind count so the panel
    // reflects it immediately instead of showing a stale number for up to a
    // minute (the cache TTL).
    invalidateBehindCache(projectId);
    
    log('info', 'Push completed', { filesAffected, commitSha: newCommitData.sha });
    
    // Create a checkpoint after successful GitHub push for version tracking
    try {
      const checkpoint = await createCheckpoint(
        projectId,
        `GitHub push: ${commitMessage}`,
        {
          checkpointType: 'manual',
          includeDbSnapshot: false, // no need for DB snapshot on git push
          // Task #1469 — Git sync (post-push) checkpoint
          source: 'git_sync',
        }
      );
      if (checkpoint) {
        log('info', 'Checkpoint created after GitHub push', { checkpointId: checkpoint.id });
      }
    } catch (checkpointError: unknown) {
      const cpMsg = checkpointError instanceof Error ? checkpointError.message : 'Unknown error';
      log('warn', 'Failed to create checkpoint after GitHub push', { error: cpMsg });
      // Don't fail the push if checkpoint creation fails
    }
    
    const shortSha = typeof newCommitData?.sha === 'string' ? newCommitData.sha.slice(0, 7) : null;
    return {
      success: true,
      message: shortSha
        ? `Successfully pushed ${filesAffected} files to ${targetBranch} (${shortSha})`
        : `Successfully pushed ${filesAffected} files to ${targetBranch}`,
      filesAffected,
      errors,
      commitSha: newCommitData?.sha,
    };
  } catch (error: unknown) {
    if (error instanceof GitHubAuthError || error instanceof GitHubRateLimitError) {
      throw error;
    }
    const errMsg = error instanceof Error ? error.message : 'Push failed';
    log('error', 'Push failed', { error: errMsg });
    return { success: false, message: errMsg, filesAffected: 0, errors: [errMsg] };
  }
}

type RemoteFile = { path: string; name: string; content: string | null; sha: string; size: number };

async function fetchAllRemoteFiles(
  token: string,
  owner: string,
  repo: string,
  branch: string,
  _filePath: string = '',
  userIdOrCtx?: string | GithubAuthContext,
  onFile?: (file: RemoteFile) => Promise<void>,
  onTotal?: (total: number) => void,
): Promise<void> {
  const excludedPaths = ['node_modules', '.git', '.next', 'dist', 'build', '.cache'];

  const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;
  const treeResponse = await githubFetch(treeUrl, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'AgentFactory-App'
    }
  }, userIdOrCtx);

  if (!treeResponse.ok) {
    log('warn', 'Failed to fetch tree, falling back to contents API', { status: treeResponse.status });
    return;
  }

  const treeData = await treeResponse.json();
  if (isTreeTruncated(treeData)) {
    // Refuse a partial pull: processing GitHub's truncated tree would drop
    // files, and a subsequent push could then push those omissions as
    // deletions. Fail loudly with an actionable message instead.
    log('error', 'GitHub truncated the recursive tree — repo too large to sync completely', {
      owner,
      repo,
      branch,
      treeEntries: Array.isArray(treeData.tree) ? treeData.tree.length : 0,
    });
    throw new Error(TREE_TRUNCATED_MESSAGE);
  }
  const blobs = (treeData.tree || []).filter((item: { type: string; path: string; size?: number }) => {
    if (item.type !== 'blob') return false;
    if (excludedPaths.some(p => item.path.startsWith(p + '/') || item.path === p)) return false;
    const size = item.size ?? 0;
    if (size >= MAX_FILE_SIZE) {
      // Clear, accurate message: distinguish the configurable sync cap from
      // GitHub's hard 100MB-per-file API limit (the latter needs Git LFS).
      // Task #1964.
      const overGithubHardLimit = size >= GITHUB_HARD_LIMIT_BYTES;
      const hint = overGithubHardLimit
        ? `exceeds GitHub's 100MB per-file API limit — use Git LFS to sync this file`
        : `exceeds the ${MAX_SYNC_FILE_MB}MB sync cap (set GIT_SYNC_MAX_FILE_MB to raise it, up to GitHub's 100MB limit)`;
      log('warn', `Skipping large file: ${item.path} (${hint})`, {
        path: item.path,
        size,
        maxSize: MAX_FILE_SIZE,
        sizeMB: (size / (1024 * 1024)).toFixed(2),
      });
      return false;
    }
    return true;
  });

  log('info', `Tree fetched: ${blobs.length} files to process`, { totalTree: treeData.tree?.length });
  onTotal?.(blobs.length);

  // Memory-safe pull (Task #1964). The old approach fetched blobs in fixed
  // batches of 20 AND collected every file's full (base64) content into one
  // array before returning — so memory grew with the whole repo and a repo
  // with many large binaries could OOM. We now: (1) cap each batch by BOTH a
  // file count AND a total in-flight byte budget (always at least one file so
  // a single large file still gets fetched on its own), and (2) hand each
  // fetched file straight to `onFile` and drop its content immediately, so
  // peak memory is bounded by one batch, not the whole repo.
  const batches = planPullBatches<{ path: string; sha: string; size: number }>(blobs, {
    maxCount: PULL_BATCH_MAX_COUNT,
    maxBytes: PULL_BATCH_MAX_BYTES,
  });
  for (const batch of batches) {
    const results = await Promise.allSettled(
      batch.map(async (item: { path: string; sha: string; size: number }): Promise<RemoteFile | null> => {
        const blobUrl = `https://api.github.com/repos/${owner}/${repo}/git/blobs/${item.sha}`;
        const blobResponse = await githubFetch(blobUrl, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'AgentFactory-App'
          }
        }, userIdOrCtx);

        if (!blobResponse.ok) return null;

        const blobData = await blobResponse.json();
        let content: string | null = null;

        // Note: an empty file has `content === ""` (falsy) with
        // `encoding === 'base64'`. We must still decode it to an empty string
        // so it gets written to disk as a real 0-byte file. Treating empty
        // blobs as `null` (the old behaviour) left a DB row with no file on
        // disk, which the local-changes diff then reported as a phantom
        // "deleted" entry (e.g. .gitkeep). Distinguish a genuinely-empty blob
        // from a failed/unknown encoding by checking the encoding + type.
        if (blobData.encoding === 'base64' && typeof blobData.content === 'string') {
          try {
            const isBinary = !isTextFile(item.path.split('/').pop() || item.path);
            if (isBinary) {
              content = BINARY_CONTENT_PREFIX + blobData.content.replace(/\s/g, '');
            } else {
              content = Buffer.from(blobData.content, 'base64').toString('utf-8');
            }
          } catch {
            content = null;
          }
        }

        return {
          path: item.path,
          name: item.path.split('/').pop() || item.path,
          content,
          sha: item.sha,
          size: item.size
        };
      })
    );

    // Persist this batch and release its content before fetching the next one.
    for (const result of results) {
      if (result.status === 'fulfilled' && result.value && onFile) {
        await onFile(result.value);
      }
    }
  }
}

export async function createGitHubRepository(
  projectId: string,
  repoName: string,
  isPrivate: boolean = true,
  description?: string
): Promise<{ success: boolean; message: string; repoFullName?: string; repoUrl?: string }> {
  const project = await getProjectWithGitHub(projectId);
  if (!project) {
    return { success: false, message: 'Project not found' };
  }

  if (project.githubRepoFullName) {
    return { success: false, message: 'Project is already linked to a GitHub repository' };
  }

  const token = await getGitHubToken(project.ownerId);
  if (!token) {
    return { success: false, message: 'No GitHub token found. Please connect your GitHub account in Settings first.' };
  }

  try {
    const createRes = await githubFetch('https://api.github.com/user/repos', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
        'User-Agent': 'AgentFactory-App'
      },
      body: JSON.stringify({
        name: repoName,
        private: isPrivate,
        description: description || `Created from Yantra — ${project.name || repoName}`,
        auto_init: false,
      })
    }, project.ownerId ?? undefined);

    if (!createRes.ok) {
      const errorBody = await createRes.json().catch(() => ({}));
      const errMsg = (errorBody as Record<string, unknown>)?.message || `GitHub API error: ${createRes.status}`;
      if (createRes.status === 422) {
        return { success: false, message: `Repository "${repoName}" already exists on your GitHub account. Choose a different name or link the existing repo.` };
      }
      return { success: false, message: String(errMsg) };
    }

    const repoData = await createRes.json() as { full_name: string; html_url: string; default_branch: string };

    await db.update(projects)
      .set({
        githubRepoFullName: repoData.full_name,
        githubRepoUrl: repoData.html_url,
        githubDefaultBranch: repoData.default_branch || 'main',
      })
      .where(eq(projects.id, projectId));

    log('info', `Created GitHub repo "${repoData.full_name}" and linked to project ${projectId}`);

    return {
      success: true,
      message: `Repository "${repoData.full_name}" created and linked successfully`,
      repoFullName: repoData.full_name,
      repoUrl: repoData.html_url,
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Failed to create GitHub repository';
    log('error', `createGitHubRepository failed: ${message}`);
    return { success: false, message };
  }
}

export async function linkExistingGitHubRepo(
  projectId: string,
  repoFullName: string
): Promise<{ success: boolean; message: string; repoUrl?: string }> {
  const project = await getProjectWithGitHub(projectId);
  if (!project) {
    return { success: false, message: 'Project not found' };
  }

  if (project.githubRepoFullName) {
    return { success: false, message: 'Project is already linked to a GitHub repository' };
  }

  const token = await getGitHubToken(project.ownerId);
  if (!token) {
    return { success: false, message: 'No GitHub token found. Please connect your GitHub account in Settings first.' };
  }

  const [owner, repo] = repoFullName.split('/');
  if (!owner || !repo) {
    return { success: false, message: 'Invalid repository name. Use the format owner/repo.' };
  }

  try {
    const repoRes = await githubFetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'AgentFactory-App'
      }
    }, project.ownerId ?? undefined);

    if (!repoRes.ok) {
      if (repoRes.status === 404) {
        return { success: false, message: `Repository "${repoFullName}" not found or you don't have access.` };
      }
      return { success: false, message: `GitHub API error: ${repoRes.status}` };
    }

    const repoData = await repoRes.json() as { full_name: string; html_url: string; default_branch: string };

    await db.update(projects)
      .set({
        githubRepoFullName: repoData.full_name,
        githubRepoUrl: repoData.html_url,
        githubDefaultBranch: repoData.default_branch || 'main',
      })
      .where(eq(projects.id, projectId));

    log('info', `Linked existing GitHub repo "${repoData.full_name}" to project ${projectId}`);

    return {
      success: true,
      message: `Linked to "${repoData.full_name}" successfully`,
      repoUrl: repoData.html_url,
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Failed to link GitHub repository';
    log('error', `linkExistingGitHubRepo failed: ${message}`);
    return { success: false, message };
  }
}
