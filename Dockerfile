# ── Common base with runtime deps ──────────────────────────────────────────
FROM node:26-trixie-slim AS base
WORKDIR /app

# `apt-get upgrade` pulls the security-patched versions of the Debian (trixie)
# base-image packages at build time — clears the subset of container-scan CVEs
# (perl / util-linux / systemd / ncurses / zlib / tar / sqlite / shadow / pam …)
# that already have a fix published in trixie. CVEs without an upstream fix yet
# (local-only TOCTOU, etc.) remain until the distro patches them and the image
# is rebuilt; none are reachable from the proxy's request surface at runtime.
RUN --mount=type=cache,id=s/6745642b-69a4-4535-b2b4-b338c565fa32-/var/cache/apt,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,id=s/6745642b-69a4-4535-b2b4-b338c565fa32-/var/lib/apt/lists,target=/var/lib/apt/lists,sharing=locked \
  apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends libsecret-1-0 ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Refresh the globally-installed npm so its *bundled* node_modules (undici, tar)
# ship the patched versions. These are npm's own internals — not application
# dependencies (our app already resolves undici@8.5.0 / tar@7.5.16, both fixed) —
# but the container scanner flags the stale copies under
# /usr/local/lib/node_modules/npm/node_modules. npm is not invoked at runtime in
# the runner stages, so this is hygiene, not an exploitable runtime path.
RUN npm install -g npm@latest \
  && npm cache clean --force

# ── Builder ────────────────────────────────────────────────────────────────
FROM base AS builder

# Build tools for native module compilation
# apt-get update needed here because base's rm -rf clears the shared cache
RUN --mount=type=cache,id=s/6745642b-69a4-4535-b2b4-b338c565fa32-/var/cache/apt,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,id=s/6745642b-69a4-4535-b2b4-b338c565fa32-/var/lib/apt/lists,target=/var/lib/apt/lists,sharing=locked \
  apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
# Workspace package manifests MUST be present before `npm ci` so npm materializes
# the workspace and installs its *workspace-only* deps (e.g. safe-regex,
# @toon-format/toon — declared in open-sse/package.json, not hoisted to root).
# Without this, `npm ci` skips them and the application build fails with "Module not
# found" (root cause of the v3.8.39 Docker build break). workspaces = ["open-sse"].
COPY open-sse/package.json ./open-sse/package.json
COPY scripts/build/postinstall.mjs ./scripts/build/postinstall.mjs
COPY scripts/build/postinstallSupport.mjs ./scripts/build/postinstallSupport.mjs
COPY scripts/build/native-binary-compat.mjs ./scripts/build/native-binary-compat.mjs
ENV NPM_CONFIG_LEGACY_PEER_DEPS=true
# --ignore-scripts blocks broad dependency install/postinstall hooks, closing
# the supply-chain attack surface where a transitive dep can run arbitrary code
# at install time. better-sqlite3 still needs a native binding for the target
# platform, so rebuild and smoke-test only that known runtime dependency below.
#
# We REQUIRE a committed package-lock.json so resolved dependency versions
# are reproducible.
RUN test -f package-lock.json \
  || (echo "package-lock.json is required for reproducible Docker builds" >&2 && exit 1)
# `npm rebuild <pkg>` re-runs the package's own install script, so under npm 11 +
# `--ignore-scripts` on the parent `npm ci` it depends on npm's script-allowlist
# machinery correctly re-enabling that one package's script. Some self-hosted build
# environments (e.g. Dokploy) hit a broken/incomplete better-sqlite3 native binding
# from that indirection. Invoking `node-gyp rebuild` directly inside the package
# directory bypasses npm's script-running layer entirely and is deterministic
# regardless of npm version or ignore-scripts allowlist behavior.
# node-gyp comes from npm's own bundled copy (deterministic, already in the image)
# instead of `npx --yes`, which would install an arbitrary registry version
# on-demand and run its lifecycle scripts (Sonar docker:S6505).
#
# tls-client-node (chatgpt-web/claude-web/grok-web/lmarena/perplexity-web TLS
# impersonation) hits the same --ignore-scripts wall: its own postinstall.js
# fetches a platform .so/.dylib/.dll from the bogdanfinn/tls-client GitHub
# Releases API and is never invoked when npm ci skips lifecycle scripts. Unlike
# better-sqlite3 above, that script never throws on failure — it only
# `console.warn`s and exits 0 — so a rate-limited or offline build would
# otherwise succeed silently with an empty bin/ and only fail at first request
# in production (TlsClientUnavailableError, #7802). Pin the native release:
# v1.16.0 ships only xgo-named assets, which tls-client-node@0.2.0 cannot find.
# v1.15.1 still supplies its expected filenames. Verify the exact Linux asset
# against the SHA-256 published at:
# https://github.com/bogdanfinn/tls-client/releases/tag/v1.15.1
# Missing, empty, or corrupt binaries must still fail the build.
RUN --mount=type=cache,id=s/6745642b-69a4-4535-b2b4-b338c565fa32-/root/.npm,target=/root/.npm \
  npm ci --no-audit --no-fund --legacy-peer-deps --ignore-scripts \
  && (cd node_modules/better-sqlite3 \
      && node /usr/local/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js rebuild) \
  && node -e "require('better-sqlite3')(':memory:').close()" \
  && TLS_CLIENT_VERSION=1.15.1 node node_modules/tls-client-node/scripts/postinstall.js \
  && (case "$(node -p process.arch)" in \
        x64) tls_asset=tls-client-linux-ubuntu-amd64-1.15.1.so; \
             tls_sha256=e393e866060e238bc36509f853293cebf5af8286aede59814462693efb603b1e ;; \
        arm64) tls_asset=tls-client-linux-arm64-1.15.1.so; \
               tls_sha256=048b75c4fb0898a306228198d545eece39a7d5348200487f0395fbdc4168fe39 ;; \
        *) echo "Unsupported tls-client-node Docker architecture" >&2; exit 1 ;; \
      esac \
      && test -f "node_modules/tls-client-node/bin/$tls_asset" \
      && test -s "node_modules/tls-client-node/bin/$tls_asset" \
      && echo "$tls_sha256  node_modules/tls-client-node/bin/$tls_asset" | sha256sum -c - \
      && mkdir -p /opt/omniroute-tls/bin \
      && cp "node_modules/tls-client-node/bin/$tls_asset" "/opt/omniroute-tls/bin/$tls_asset" \
      && echo "$tls_sha256  $tls_asset" > /opt/omniroute-tls/SHA256SUMS \
      || (echo "tls-client-node native binary missing or invalid after postinstall (#7802)" >&2 && exit 1))

# Build with Turbopack (stable in Next 16, the repo default). The v3.8.27-era
# TurbopackInternalError panic ("entered unreachable code: there must be a path to a
# root" in ImportTracer::get_traces) no longer reproduces on Next 16.2.9 — validated
# 2026-07-05 with clean amd64 (12min14s, image smoke-tested: /api/monitoring/health
# 200) and arm64 (qemu, exit 0, zero panic strings) builds. Turbopack cut the bare
# build from 17min to 9min on the same 32-core box. Webpack stays available as the
# escape hatch: `--build-arg`/-e OMNIROUTE_USE_TURBOPACK=0.
# See docs/ops/QUALITY_GATE_PLAYBOOK.md Parte 6.
ENV OMNIROUTE_USE_TURBOPACK=1

# Next.js basePath is fixed at build time; pass OMNIROUTE_BASE_PATH here when the
# image should serve under a reverse-proxy subpath without a runtime patch.
ARG OMNIROUTE_BASE_PATH=""
ENV OMNIROUTE_BASE_PATH=$OMNIROUTE_BASE_PATH

# Docker containers cannot run the MITM/Agent-Bridge stack (no host DNS/cert
# access), so keep @/mitm/manager on the graceful stub (#3390). This flag is
# Docker-only: npm/Electron/VPS builds must bundle the REAL manager (#6344).
ENV OMNIROUTE_MITM_STUB=1

# Raise the V8 heap ceiling for the build. The webpack production optimization
# pass needs more than V8's default ceiling (~2 GB) for a codebase this size; a
# memory-constrained Docker build otherwise dies with "FATAL ERROR: ... JavaScript
# heap out of memory" during the builder stage (#4076). Turbopack's compile is
# native (Rust) and less V8-heap-bound, but the prerender/export phase still runs
# on V8, so keep the ceiling. NODE_OPTIONS propagates to the spawned `next build`
# child (build-next-isolated.mjs → resolveNextBuildEnv spreads process.env).
# Build-only; the runtime heap is set separately on the runner stage
# (OMNIROUTE_MEMORY_MB). Override: `--build-arg OMNIROUTE_BUILD_MEMORY_MB=6144`.
ARG OMNIROUTE_BUILD_MEMORY_MB=4096
ENV NODE_OPTIONS="--max-old-space-size=${OMNIROUTE_BUILD_MEMORY_MB}"

COPY . ./
RUN --mount=type=cache,id=s/6745642b-69a4-4535-b2b4-b338c565fa32-/app/.build/next/cache,target=/app/.build/next/cache \
  mkdir -p /app/data && npm run build

# ── Runner base ────────────────────────────────────────────────────────────
FROM base AS runner-base

LABEL org.opencontainers.image.title="omniroute" \
  org.opencontainers.image.description="Unified AI proxy — route any LLM through one endpoint" \
  org.opencontainers.image.url="https://omniroute.online" \
  org.opencontainers.image.source="https://github.com/diegosouzapw/OmniRoute" \
  org.opencontainers.image.licenses="MIT"

ENV NODE_ENV=production
ENV PORT=20128
ENV HOSTNAME=0.0.0.0
# Runtime heap ceiling. 1024MB is enough for normal traffic but can be tight
# for large fusion-combo panels (many models fanned out in parallel, each
# response buffered in full — see open-sse/services/fusion.ts::FUSION_DEFAULTS
# .maxPanel, issue #1905). Override at `docker run` time with
# `-e OMNIROUTE_MEMORY_MB=2048` (or higher) if you raise fusionTuning.maxPanel
# above the default cap.
ENV OMNIROUTE_MEMORY_MB=1024
ENV NODE_OPTIONS="--max-old-space-size=${OMNIROUTE_MEMORY_MB}"

# Data directory inside Docker — must match the volume mount in docker-compose.yml
ENV DATA_DIR=/app/data
RUN mkdir -p /app/data

# `npm run build` (build-next-isolated → assembleStandalone) bundles ALL runtime
# files into .build/next/standalone/ — .next, node_modules, migrations, scripts,
# docs, and the previously hand-COPY'd modules below (@swc/helpers, pino-*, split2,
# migrations). assembleStandalone copies them straight from the builder's
# node_modules, so they are present regardless of NFT/Turbopack trace behaviour.
# The old per-module overrides were therefore pure duplication and were removed
# (build-output-isolation cleanup). See scripts/build/assembleStandalone.mjs
# (EXTRA_MODULE_ENTRIES) for the single source of truth.
COPY --from=builder /app/.build/next/standalone ./
# better-sqlite3 is the one exception still copied explicitly: assembleStandalone
# only syncs its native build/ dir; the JS wrapper (lib/, package.json) is left to
# Next.js tracing. bootstrap-env requires SQLite BEFORE the standalone server
# starts, so guarantee the complete package independent of trace behaviour.
COPY --from=builder /app/node_modules/better-sqlite3 ./node_modules/better-sqlite3
# Keep the verified native asset outside /app/data, which a mounted volume hides.
# /opt stays root-owned; the non-root entrypoint seeds the actual writable cache.
COPY --from=builder /opt/omniroute-tls /opt/omniroute-tls
# Reuse the application's exact DATA_DIR / legacy-home / XDG resolution logic.
# The image's Node 26 runtime supports this standalone TypeScript module natively.
COPY --from=builder /app/src/lib/dataPaths.ts /opt/omniroute-tls/dataPaths.ts
COPY --chmod=644 <<'TLS_CACHE_SCRIPT' /opt/omniroute-tls/prepare-cache.mjs
import { createHash } from "node:crypto";
import {
  lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  renameSync, rmSync, writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { resolveDataDir } from "./dataPaths.ts";

const prefixes = {
  x64: "tls-client-linux-ubuntu-amd64-",
  arm64: "tls-client-linux-arm64-",
};
const prefix = prefixes[process.arch];
if (process.platform !== "linux" || !prefix) {
  throw new Error("Unsupported tls-client-node Docker platform/architecture");
}
const asset = `${prefix}1.15.1.so`;
const manifest = readFileSync(new URL("./SHA256SUMS", import.meta.url), "utf8").trim();
const [expectedHash, manifestAsset, extraField] = manifest.split(/\s+/);
if (extraField || !/^[a-f0-9]{64}$/.test(expectedHash) || manifestAsset !== asset) {
  throw new Error("Invalid tls-client-node image checksum manifest");
}
const source = new URL(`./bin/${asset}`, import.meta.url);
if (!lstatSync(source).isFile()) {
  throw new Error("tls-client-node image binary is not a regular file");
}
const bytes = readFileSync(source);
const sha256 = (content) => createHash("sha256").update(content).digest("hex");
if (!bytes.length || sha256(bytes) !== expectedHash) {
  throw new Error("tls-client-node image binary checksum mismatch");
}

const dataDir = resolveDataDir();
mkdirSync(dataDir, { recursive: true });
const cacheDir = join(dataDir, "tls-client", "bin");
for (const dir of [join(dataDir, "tls-client"), cacheDir]) {
  try {
    mkdirSync(dir);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  if (!lstatSync(dir).isDirectory()) {
    throw new Error("tls-client-node cache path must be a directory, not a symlink");
  }
}
// tls-client-node@0.2.0 selects the lexically last matching cache filename.
// Preserve existing files, but never let a different asset win over the image pin.
function assertPinnedSelection() {
  const candidates = readdirSync(cacheDir)
    .filter((name) => name.startsWith(prefix) && name.endsWith(".so"));
  if ([...candidates, asset].sort().at(-1) !== asset) {
    throw new Error("Conflicting tls-client-node cache version; refusing an unverified binary");
  }
}
assertPinnedSelection();
const destination = join(cacheDir, asset);
try {
  if (!lstatSync(destination).isFile()) {
    throw new Error("tls-client-node cache binary must be a regular file, not a symlink");
  }
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}
// Atomic replacement repairs corrupt/empty copies and avoids partially-written
// libraries on cold starts or concurrent starts sharing the same data volume.
const staging = mkdtempSync(join(cacheDir, ".image-binary-"));
try {
  const temporary = join(staging, asset);
  writeFileSync(temporary, bytes, { mode: 0o755, flag: "wx" });
  renameSync(temporary, destination);
} finally {
  rmSync(staging, { recursive: true, force: true });
}
assertPinnedSelection();
if (sha256(readFileSync(destination)) !== expectedHash) {
  throw new Error("tls-client-node cache binary checksum mismatch");
}
// Hand the normalized path to the child so bootstrap and provider resolution
// cannot diverge on whitespace, relative paths, or an empty DATA_DIR override.
console.log(dataDir);
TLS_CACHE_SCRIPT
COPY --chmod=755 <<'TLS_CACHE_ENTRYPOINT' /opt/omniroute-tls/start.sh
#!/bin/sh
set -eu
DATA_DIR="$(node /opt/omniroute-tls/prepare-cache.mjs)" || exit 1
export DATA_DIR
exec "$@"
TLS_CACHE_ENTRYPOINT
# migrations land at <standalone>/migrations via assembleStandalone; point the runtime at them.
ENV OMNIROUTE_MIGRATIONS_DIR=/app/migrations

# Docker healthcheck script — not traced by Next.js standalone output, so copy
# it explicitly. The HEALTHCHECK CMD references it as `node healthcheck.mjs`.
COPY --from=builder /app/scripts/dev/healthcheck.mjs ./healthcheck.mjs

# Hand /app over to the baked-in `node` non-root user (UID/GID 1000) so the
# runtime process never holds root privileges. The chown happens after all
# COPYs so it covers files originally owned by root in the builder stage.
RUN chown -R node:node /app

EXPOSE 20128

# Drop to non-root before ENTRYPOINT/CMD so every derived stage (runner-cli,
# runner-web) also runs as a non-root user unless they explicitly switch back.
USER node

# Warns if the mounted data volume has wrong ownership
COPY --chmod=755 scripts/check-permissions.sh /tmp/check-permissions.sh
# check-permissions.sh repairs the default volume (when root) and drops to node
# BEFORE start.sh verifies/seeds the cache. Both wrappers preserve CMD and signals.
ENTRYPOINT ["/tmp/check-permissions.sh", "/opt/omniroute-tls/start.sh"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "healthcheck.mjs"]

CMD ["node", "dev/run-standalone.mjs"]

# ── Runner Web (web-cookie providers: Gemini Web, Claude Turnstile) ───────────
#
#  Two image flavors:
#    runner-base  →  omniroute:VERSION        Lean base (~500 MB). No browsers.
#    runner-web   →  omniroute:VERSION-web    +Chromium/Playwright (~800 MB).
#
#  Use runner-web when you need web-cookie providers (gemini-web, claude-web,
#  claude-turnstile). For all other providers runner-base is sufficient.
#
#  Build:
#    docker build --target runner-web -t omniroute:web .
#  Compose:
#    build:
#      context: .
#      target: runner-web
FROM runner-base AS runner-web

USER root

# Copy playwright and playwright-core from the builder stage.
# The slim runtime image does not have playwright in node_modules, so npx falls
# back to a registry download — unreliable on CI runners (exits 127 on failure).
# Copying from the builder avoids any network access at image-build time and also
# ensures the same playwright version is available at runtime for web-session providers.
COPY --from=builder /app/node_modules/playwright-core ./node_modules/playwright-core
COPY --from=builder /app/node_modules/playwright ./node_modules/playwright

# Install Playwright browser binaries + OS dependencies under root, then hand
# ownership of the browsers cache to the node user.
# PLAYWRIGHT_BROWSERS_PATH overrides the default ~/.cache/ms-playwright so the
# browsers land under /home/node which persists across image layers and is
# accessible to the non-root runtime user.
ENV PLAYWRIGHT_BROWSERS_PATH=/home/node/.cache/ms-playwright
RUN --mount=type=cache,id=s/6745642b-69a4-4535-b2b4-b338c565fa32-/var/cache/apt,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,id=s/6745642b-69a4-4535-b2b4-b338c565fa32-/var/lib/apt/lists,target=/var/lib/apt/lists,sharing=locked \
  apt-get update \
  && node node_modules/playwright/cli.js install chromium --with-deps \
  && chown -R node:node /home/node/.cache \
  && rm -rf /var/lib/apt/lists/*

USER node

FROM runner-base AS runner-cli

# Drop back to root briefly so we can install system + global npm packages,
# then return to the `node` non-root user before the CMD inherited from
# runner-base runs.
USER root

# Install system dependencies required by openclaw (git+ssh references).
RUN --mount=type=cache,id=s/6745642b-69a4-4535-b2b4-b338c565fa32-/var/cache/apt,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,id=s/6745642b-69a4-4535-b2b4-b338c565fa32-/var/lib/apt/lists,target=/var/lib/apt/lists,sharing=locked \
  apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates docker.io docker-compose \
  && rm -rf /var/lib/apt/lists/* \
  && git config --system url."https://github.com/".insteadOf "ssh://git@github.com/"

# Install CLI tools globally. Separate layer from apt for better cache reuse.
RUN --mount=type=cache,id=s/6745642b-69a4-4535-b2b4-b338c565fa32-/root/.npm,target=/root/.npm \
  npm install -g --no-audit --no-fund @openai/codex @anthropic-ai/claude-code droid openclaw@latest

USER node
