# Agent Instructions

<!-- DRJ:CONTEXT BEGIN v=f3d477f — generated from DRJ-Technologies/drj-context; do not edit here -->
> **Parent context:** [DRJ-Technologies/drj-context](https://github.com/DRJ-Technologies/drj-context)
> is canonical for DRJ platform patterns, preferences, and laws.
> Read the authenticated repository through `gh api` or its registered linked worktree.
> (private repo — a plain web fetch will 404; source edits require an owned linked worktree).
>
> **Everything below the END marker is repo-local and supersedes this block on conflict.**

## DRJ org context (synced — edit in drj-context, never here)

**Environment** — identify the session manager first; Herdr commands/paths/sweeps require verified Herdr scope. AgentDeck keeps its own setup. Keep agent/session/terminal IDs out of shared repos; discover contacts in the owning environment, never route from a copied UUID. → `operating.md#environment-and-session-manager`
**Secrets / configuration** — never print/log/commit credentials. All new work uses AWS Secrets Manager for credentials, SSM for centrally managed nonsecret settings and the existing ESO/ConfigMap GitOps pattern for Kubernetes; other consumers use the same AWS sources. No new Doppler dependencies. → `laws.md#secrets`, `laws.md#aws-configuration-and-eso`, `patterns.md#aws-configuration-and-eso`
**Infrastructure** — new Terraform/OpenTofu uses OTF, not Spacelift: native PR plans, main saved plans, explicit UI/robot CLI approval, no auto-apply; retain documented independent management bootstrap exception and Kubernetes GitOps. IAM: Governance owns lifecycle/trust/boundaries/fences; Product owns scoped grants on pre-vended deployment AND runtime roles; workload state owns business resources. New IAM follows now; existing roles need staged preservation/capacity proof. → `laws.md#infrastructure-delivery-through-otf`, `operating.md#native-otf-gitops`, `laws.md#iam-ownership-and-capacity`, `patterns.md#iam-ownership-and-staged-adoption`
**Istio** — new or materially changed app workloads in Istio-equipped clusters enroll in ambient from first deployment through the owner's Pod-template pattern; mesh callers use native Service DNS or already-qualified global imports with narrow export and exact principals; callers outside the mesh use the private Istio gateway; never new private Traefik/NLB paths or extra LB hops. First identify cluster, mesh (`drj-prod`, `drj-nonprod`, `drj-build` stay separate), trust domain and owners; keep TLS, datastore semantics, capacity and app auth; prove rendered config plus live capture/transport/health. Explicit owned exceptions only; YMP held. → `laws.md#istio-ambient-by-default`, `patterns.md#istio-ambient-workloads`
**Co-founders** — Dan and Rob have equal DRJ permissions under their own identities; no Dan-only build, publish, deploy or admin gate. Preserve common safeguards and separate credentials/sessions. → `laws.md#co-founder-access-parity`
**Business continuity** — never pause shared business workers for migrations or cutovers: buying, confirmation, rejection and fulfillment must stay available. Isolate the affected publisher/consumer or use a compatible staged migration; otherwise hold and redesign the migration. → `laws.md#keep-business-workers-running`
**Upstream first** — native interfaces, one implementation, inputs once. Separate GitOps and runtime code; use shared Flyway for owned PostgreSQL. Remove mirrors, copied hashes and retired tools. Custom gates need a concrete gap; retain tests, access/privacy/bounds, custody and safeguards. → `operating.md#process-only-if-absolutely-needed`, `patterns.md#kubernetes-source-and-deployment-repositories`, `patterns.md#database-migrations-with-flyway`
**Process** — only if absolutely needed: rigor (main-proven inputs, receipts, repeated review rounds) for irreversible actions only; docs/plans/coordination stay light; one review round, merges at the reviewed head; no maintenance windows unless the owner asks; act autonomously, never route approvals to the owner; leads drive the accepted plan to full delivery with no idle lanes. → `operating.md#process-only-if-absolutely-needed`, `#act-autonomously-never-route-approvals-to-the-owner`, `#leads-drive-the-plan-to-full-delivery`
**CI** — essential tests; Temporal/Dagger Linux checks; every service enrolled, native providers observed and holds explicit. Fleet reads shared CI status/logs; no agent polling loops or personal-token fallback. → `operating.md#universal-service-ci-and-shared-observation`, `#keep-permanent-ci-essential`
**Teams** — autonomous: own your members, reviewers and infrastructure; app teams may change and roll out platform systems for their usage through approved paths with their own identities. Coordinate actual shared conflicts lead-to-lead; no global queue approval or default maintenance ceremony. Preserve review/CI/main-only provenance/holds; never replay or interrupt other owners' operations. Never share workers; bias toward N independent coders and one reviewer per PR with project context and an author brief. Only leads communicate across teams; members inspect read-only. → `operating.md#team-ownership-and-cross-team-boundaries`
**Communication** — keep routine agent handoffs and technical bookkeeping in internal channels/work records, not the owner's chat; leads report brief plain-language progress, outcomes and material blockers, without echoing raw reports. Keep evidence available; include technical detail when requested or needed for a result, risk or owner decision. → `operating.md#keep-internal-coordination-out-of-owner-updates`
**Unfamiliar tools** — read the real interface and prove it on one row first; plausible output can be wrong. → `operating.md`
**Model allocation** — coder fleet: OpenAI/Codex and Anthropic/Claude Code only. Start with Sol 6.1/xhigh for general engineering, Opus 5.5 for demanding work/review, Astra 6/xhigh for escalation. Follow dated task-fit guidance and fresh capacity; preserve active owners and holds. → `operating.md#model-and-account-aware-planning`
**GitHub** — use `gh` and verify DRJ access before pushing; on SSH-agent failure use the
`gh` credential wrapper. → `patterns.md#git-and-github`
**Stacked PRs** — prefer native GitHub stacks for dependent changes; preserve ownership, checks and merge scope. → `operating.md#prefer-github-stacked-pull-requests`
**Branches** — `agent/<slug>-YYYYMMDD`; other prefixes for human-initiated work.
The date suffix is required; use conventional commit subjects. → `patterns.md#branches-and-commits`
**Shell** — use `cp -f`, `mv -f`, `rm -f` to avoid interactive aliases. → `patterns.md#non-interactive-shell-commands`
**Shared hosts** — on disk/resource pressure, first free only your own temp, stopped containers and volumes, plus unused build cache and journal; escalate the rest. → `operating.md#shared-host-resources-fix-what-you-safely-can`
**SSM** — no `->`, `()`, heredocs, or streaming commands like `journalctl -f`;
append `|| true` so a correct command doesn't report `Status: Failed`.
→ `patterns.md#ssm-command-escaping`
**Docs** — short instruction routers; one canonical runbook per distinct recurring
operation. Link, don't copy; edit in place, retire obsolete duplicates and fix links.
Keep current status compact; PR/CI records hold routine detail. Historical logs are not current posture; runbooks win over drifting agent files.
→ `patterns.md#documentation-structure`
**Agent files** — `AGENTS.md` is canonical and real; `CLAUDE.md` is a git
symlink to it. After creating one, verify `git ls-files -s CLAUDE.md` prints
mode `120000` — a `core.symlinks=false` checkout silently commits a text file
instead and looks fine locally. → `patterns.md#agent-files`
**Roadmaps/docs** — update only for material shifts that merged code, PRs and receipts
don't already document; batch them (a few per day at most), never one docs PR per merge
or milestone. When authorized, publish the browser view and verify the served revision
in Chrome/Chromium. → `operating.md#keep-roadmaps-and-browser-views-current`
**UI/UX** — use task-fit models; verify rendered interfaces, user journeys and accessibility. With a catalog: component change ⇒ story change ⇒ green story tests ⇒ story ids in the PR.
→ `operating.md#uiux-design-and-verification`, `#keep-the-component-catalog-current`
**Worktrees/tasks** — agents own linked worktrees; keep each team together in its project workspace.
Leads accept tested-head task receipts before worker cleanup; preserve source/history.
→ `operating.md#lead-owned-task-receipts-and-passive-events`, `#agent-completion-and-workspace-closure`
<!-- DRJ:CONTEXT END -->

