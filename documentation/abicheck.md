# Advisory ABI/API check (abicheck)

An advisory shadow check that reports ABI/API changes to `libpvxs` and
`libpvxsIoc` on a pull request. It never gates: `abi-diff.sh` (ABICC) remains
authoritative. This page is the maintenance guide — how it is wired, what it
compares against, how to read an outcome, and what it cannot yet do.

## Setup

Three files describe the whole integration; everything else is a reference to
a pinned abicheck Action.
| File | Role |
|---|---|
| `.ci-local/abicheck-components.json` | which library owns which installed headers |
| `.ci-local/abicheck.yml` | how the public headers are parsed for extraction |
| `.github/actions/abicheck-capture/action.yml` | EPICS build-context resolution, then one `uses:` |

Every abicheck Action is pinned to one merged, immutable revision, named once
per workflow as `ABICHECK_REF`.

## Selected surface and profile

`libpvxs` owns every installed `include/pvxs/*.h` except `iochooks.h`;
`libpvxsIoc` owns only `iochooks.h`. The installed core headers and the EPICS
Base include roots are *parser context* for both — an include root never
widens what a component is held responsible for.

Two assertions in the declaration are deliberate, because a glob alone would
lose them and a pattern matching nothing is a hard error upstream:

- `versionNum.h` is named explicitly *as well as* matched by `*.h`. Without
  that, a missing generated header resolves silently to the remaining
  headers and every `versionNum` declaration reports as removed.
- `header_exclude` on `iochooks.h` fails if that header ever moves, so
  `libpvxs` cannot quietly re-acquire its sibling's declarations.

One profile is analysed —
`linux-x86_64-gcc-default-base7.0-bundled-libevent`: native Linux x86_64,
GCC, shared (default) configuration, EPICS Base 7.0, PVXS's bundled libevent.
That name is the compatibility key; snapshots and baselines must share it.

## Build reuse

The capture runs inside the existing `Native Linux (WError)` matrix leg — the
one carrying the `abicheck: 1` marker — after that leg's own tests. There is
no second build, no second dependency preparation and no source-tree input:
it reads the headers in `include/pvxs` and the shared objects in
`lib/$EPICS_HOST_ARCH` that `cue.py build` installed.

It runs even when that leg's tests failed, as long as the build produced an
installation: an unrelated red test must not hide an ABI finding. Each
component is captured **once** and the resulting snapshots are reused for
both baseline channels and for rendering; nothing re-extracts.

## Evidence depth

`--depth headers` (L2): exported symbols and DWARF, plus the public header
AST. **Build-flag and toolchain drift (L3) are not covered**, and L4/L5
source evidence is neither collected nor enabled implicitly. Absent optional
evidence stays honestly absent.

## Baseline policy

Two questions, separately labelled, never merged into one number:

| Channel | Old side | Answers |
|---|---|---|
| `accepted-main` | the `ci-scripts-build.yml` push run for the PR's **exact base commit** | what did this pull request introduce? |
| `release-contract` | a release asset published only from a tag build | what changed since the selected supported release? |

`accepted-main` is declared **only on pull-request events** — a push or tag
build has no PR base, and declaring it there would manufacture a missing
check for a question nobody asked.

Eligibility is `actions/verify-baseline-source`, not shell here: tags are
resolved through `refs/tags/<name>` explicitly (a revision endpoint would
resolve a *branch*), annotated tags are peeled, no `v` prefix is assumed
(PVXS tags are bare versions such as `1.5.2`), the capture must belong to the
tagged commit, and `not_found` stays distinct from `lookup_failed`. PVXS
still fetches the bytes; only the decision is upstream's.

A missing, expired, wrong-profile or incompatible baseline is an explicit
incomplete outcome, never a clean result.

## Baseline publication and bootstrap

`.github/workflows/abicheck-baseline.yml` publishes the `release-contract`
asset through abicheck's own reusable `publish-baseline.yml`, which owns
packaging, the manifest/schema/profile/generation/digest gate, tag resolution
and the immutability chain (identity-verified idempotent republish,
fail-closed on a conflicting asset — not filename-only idempotence, and no
silent clobber). PVXS has no publisher of its own.

- **Automatic.** A tag build already captured the tagged revision. A
  `mode: tag` gate confirms the pushed ref really is a tag naming the commit
  that was built; publication then takes the bytes from that
  already-completed producer run through the API, with the run's repository,
  workflow, event, id, attempt and conclusion each verified and the artifacts
  selected by their own ids. A pull-request-triggered producer is refused
  unconditionally.
- **Bootstrap** (`workflow_dispatch`, one-time per release). A historical
  release predates the integration, so no tag build of it ever produced a
  set, and dispatching the old workflow cannot help — the workflow *at* that
  tag has no capture step. This path builds the requested revision once with
  PVXS's normal build commands and the same component declaration as the
  candidate, then captures it.

The publication tag and the revision a set records are two different
identifiers: `expected-project-ref: commit` resolves the tag and requires the
set's own `project_ref` to equal that commit. A SHA-valued manifest is never
rewritten to satisfy a tag-valued validator.

## Permissions and deployment

| Job | Scope | Runs |
|---|---|---|
| capture + comparison (`ci-scripts-build.yml`) | `contents: read`, `actions: read`, no secrets | contributor code, including forks |
| `bootstrap-build` | `contents: read` | the historical revision's own build code |
| publication (`abicheck-baseline.yml`) | `contents: write`, `actions: read` | reviewed pinned code only |
| `abicheck-report.yml` | `actions: read`, `pull-requests: write` | reviewed pinned code only |

The read-only build and the write-capable publication are separate jobs, and
the write-capable half refuses to run off anything but the default branch.
Contributor code never runs with write credentials, and
`pull_request_target` is never used.

**Deployment prerequisite:** `workflow_run` only ever runs the default-branch
copy of a workflow file. Until a maintainer merges `abicheck-report.yml`
there, no pull request — including the one that adds it — publishes a
comment. That is by design.

## Interpreting an outcome

The producer writes one canonical aggregate document over every declared
check and renders abicheck's own bounded summary of it into the job summary.
Read these four values:

- `coverage` — `complete`, `partial` or `empty`. **`empty` means no
  comparison was completed.** The cause comes from the document's structured
  outcomes, not from the count: zero analyses can mean an unavailable
  baseline, a failed capture, or a corrupt report.
- `status` — the document's own `pass`/`fail`.
- `compatibility-exit` — `abicheck aggregate`'s own `0`/`1`/`2`/`4`. It never
  fails the step; that is what keeps this advisory.
- `channels` — the roll-up per baseline channel, so "the release comparison
  is missing" is distinguishable from "one component is missing".

A refused declaration, a usage error, or a document that does not describe a
real outcome **fails** the aggregate step, so operational loss cannot reach
the publisher disguised as an empty finding set.

Every comparison also reports a few hundred non-gating `risk` changes: an
independent rebuild of a revision compared against *itself* still yields
several hundred, so that is the noise floor of a known upstream attribution
defect, not change — and part of why this stays advisory.

## Publication to the pull request

The analysis is unprivileged and cannot comment. `abicheck-report.yml` is a
separate trusted `workflow_run` publisher built from two reviewed Actions:
`verify-source-run` establishes which run, which pull request and which
commit was actually analysed — from the API, never from the artifact — and
`report` renders the document as one sticky comment per PR and profile,
covering both components with the baseline channels separately labelled.

The artifact is acquired **once**: `provenance-from` reads the producer's
recorded `analysis_context` out of the same extraction, and `report-from`
returns the document together with the identity it was checked under. On a
`pull_request` run the analysed revision is an ephemeral merge commit no API
endpoint names; `require-provenance: true` means an artifact recording no
context is refused rather than silently reported as the PR head. Ordering is
by the **producing** run, so a late re-run of an older commit cannot
overwrite a newer result.

Safe publication is not independent attestation: the report's contents remain
contributor-generated evidence. What is enforced is the recipient and the
execution boundary.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `coverage=empty`, no comparison | no candidate artifact (capture failed or the leg did not run), or both channels unavailable — read `channels` |
| accepted-main unavailable on a PR | the base commit has no successful push run carrying a capture artifact, or it expired |
| release-contract unavailable | no published final release carries the asset for this profile — run the bootstrap once |
| capture refuses by name | a declared header or exclusion pattern matched nothing (usually `versionNum.h` not generated, or `iochooks.h` moved) |
| `wrong_profile` / `stale_generation` | the baseline was captured under a different build arrangement or scanner generation |
| a comparison looks wrong after a rebuild | check for a stale mutated `include/` tree in a shared checkout; it is a gitignored build output |

## Current limitations

- **`actions/report` cannot be loaded at the pinned revision.** Two of its
  input *descriptions* quote `${{ github.event.workflow_run.id }}` and
  `${{ github.event.workflow_run.run_attempt }}` as usage examples. Actions
  evaluates expressions inside action metadata, and the `github` context does
  not exist there, so the file fails template validation and the job dies in
  "Set up job" before any step runs. It is unconditional, independent of the
  inputs a caller passes, and upstream's to fix; `abicheck-report.yml`
  therefore cannot publish yet. Nothing is reimplemented here to route around
  it — the job summary states the outcome from the aggregate's own outputs.
- **C++17 extraction.** PVXS's supported consumer language mode is C++11, but
  the extraction pipeline cannot parse these headers against libstdc++ 13 in
  C++11 or C++14. C++17 extraction is a disclosed deviation and is **not**
  validation of C++11 consumer behaviour.
- **Ownership attribution.** EPICS Base and libstdc++ symbols reached only
  through `-I` roots are still attributed to `libpvxs`, and `pvxs::version_*`
  to `libpvxsIoc`. Both fold to zero gating findings and are labelled
  pre-existing on both sides. No suppressions are added here.
- **No published baselines yet.** The fork has tags but no GitHub Releases
  carrying the asset, and `master` does not yet contain the integration, so
  no push run of a base commit has produced a candidate artifact. Both are
  reported as missing coverage rather than worked around.

Measurements, comparison transcripts and the upstream issue references live
in the pull request discussion, not here.
