# Advisory ABI/API check (abicheck)

PVXS's authoritative ABI check is ABICC, driven by `abi-diff.sh` from
`.github/workflows/release.yml`. Nothing here changes that. This document
describes the *advisory* abicheck integration that runs alongside it during
shadow adoption.

## What it does

    normal candidate build (one existing matrix leg)
        -> capture libpvxs and libpvxsIoc once, at L2
        -> compare against reusable, explicitly identified baselines
        -> retain canonical reports and diagnostics
        -> trusted, report-only publisher
        -> one pull-request comment covering both components

There is exactly **one build** and **one capture per component per
revision**. The capture is reused for every comparison, for the job summary
and for the pull-request comment. Rendering never re-extracts and never
re-compares.

## Build reuse

The capture runs inside the existing `Native Linux (WError)` leg of
`.github/workflows/ci-scripts-build.yml` — the one configuration carrying the
`abicheck: 1` marker. It reads what `cue.py build` installed:

* `include/pvxs/*.h` — the installed public headers, including the generated
  `versionNum.h`
* `lib/$EPICS_HOST_ARCH/libpvxs.so.*`, `lib/$EPICS_HOST_ARCH/libpvxsIoc.so.*`
  — the real shared objects, not the symlinks and not the static archives
* the EPICS Base include roots `cue.py prepare` had already set up, read from
  `configure/RELEASE.local`

It does not reconstruct EPICS Makefile internals, copy headers out of `src/`
or `ioc/`, rewrite EPICS configuration, or move `HOME`. It runs after the
leg's own tests so nothing else that needs the checkout is disturbed, and it
runs even if those tests failed, as long as the build produced an
installation — an unrelated red test must not hide an ABI finding.

`.ci-local/abicheck-inputs.sh` resolves and validates those inputs and emits
the capture Action's `libraries` declaration. It contains no build
orchestration, no report schema and no gate logic.

## Ownership

| Component | Owned public surface | Include-only context |
|---|---|---|
| `libpvxs` | Every installed `include/pvxs/*.h` except `iochooks.h` | `include/`, EPICS Base `include/`, `include/os/Linux`, `include/compiler/gcc` |
| `libpvxsIoc` | `include/pvxs/iochooks.h` only | the same roots, plus the installed core headers |

An include search root is context for the parser. It is not a declaration
that the component must export everything reachable through it. See "Known
issues" — abicheck does not honour that distinction correctly yet.

## Evidence depth

`--depth headers` (L2): exported symbols and DWARF (L0/L1) plus the public
header AST.

This is a **deliberate reduction** from the previous integration, which ran
Bear over a rebuild of both revisions to reach L3. Build-flag and toolchain
drift are **no longer covered**. L4 and L5 source evidence are not collected
and must not be enabled implicitly. Debug information is whatever the normal
build produced; no special build is performed to obtain it, and coverage is
reported as it actually is.

## Extraction context

`.ci-local/abicheck.yml` pins `-std=c++17` for header parsing only. PVXS's
supported consumer mode and its own build are C++11; parsing the public
headers in C++11 or C++14 against the runner's libstdc++ 13 is not possible
with the supported CastXML (0.7.0, Clang 20). This is a disclosed deviation
of the extraction context, applied identically to both components and to both
sides of every comparison. `PVXS_API_BUILDING` and `PVXS_ENABLE_EXPERT_API`
are deliberately not defined: the headers are parsed as an ordinary consumer
sees them.

## Baselines

Two separate questions, never merged into one number:

* **accepted-main** — what did this pull request introduce? Resolved by
  downloading the `ci-scripts-build.yml` run for the pull request's *exact
  base commit*, and rejected by `check-target` if the baseline's recorded
  `project_ref` is not that commit. No cache restore-key prefix matching.
* **release-contract** — what changed since the selected supported release?
  A `abicheck-baseline-<profile>.tar.zst` release asset, published by
  `.github/workflows/abicheck-baseline.yml` from a tag build only.

Both are resolved by explicit revision, component and profile. The profile
id — `linux-x86_64-gcc-default-base7.0-bundled-libevent` — names the build
arrangement, including PVXS's bundled libevent rather than the system one, so
a baseline from a different arrangement resolves as `wrong_profile` rather
than being silently compared.

A missing, expired, wrong-profile or incompatible baseline produces an
explicit unavailable/incomplete outcome. It never produces a clean result.

For a historical release with no usable evidence, build that tag once with
`workflow_dispatch` and publish the capture with
`abicheck-baseline.yml`'s own `workflow_dispatch` inputs. The result is
retained; nothing is rebuilt per pull request.

## Publication

`.github/workflows/abicheck-report.yml` is a separate, trusted publisher:

* The analysis workflow has `contents: read` and no secrets. It is never
  given write access to make a comment work, and contributor code is never
  run under `pull_request_target`.
* The publisher runs from the default branch on `workflow_run`, with only
  `actions: read` and `pull-requests: write`.
* It verifies the producer run's repository, workflow path, event, run id and
  attempt; resolves the pull request through the API rather than trusting
  anything in the artifact; distinguishes the pull request head SHA from the
  merge commit that was actually built and verifies their association;
  downloads only from that exact run; and treats every byte of the artifact
  as untrusted data.
* It never checks out, installs, imports or executes pull-request code or
  pull-request-built binaries, and it runs no analysis.
* A publication failure fails visibly and is never reported as a clean
  compatibility result. A failed or missing analysis is published as an
  explicit incomplete state.

A trusted reporter does not make contributor-produced report contents trusted
evidence. Origin and assurance are preserved; what is enforced is who the
result is delivered to and what executes while delivering it.

**Deployment prerequisite:** `workflow_run` only ever runs the copy of the
publisher on the default branch. Until a maintainer merges it there, no pull
request — including the one introducing it — will publish a comment.

## Gate policy

Advisory (`gate-mode: advisory`) during shadow adoption. Gate status and
compatibility are reported separately: the check can be green while
prominently reporting a detected break. ABICC remains authoritative.

## Known issues (abicheck product bugs, measured 2026-09-16)

Reproduced on this branch with abicheck
`3737f9f960ae14a7b24dbb6e9b686e49fb563673` and CastXML 0.7.0, by comparing a
snapshot against itself (a byte-identical pair, verdict `NO_CHANGE`):

1. **Include-context headers become export obligations.** 123 EPICS Base
   symbols (`epicsMutex::lock()`, `epicsEvent::wait()`, `errVerbose`, …) are
   charged to `libpvxs` as its own missing exports, and `pvxs::version_str()`
   and friends are charged to `libpvxsIoc`. Both are reached only through
   `-I` include roots.
2. **Persistent hygiene findings are reported as changes.** An unchanged
   library reports 505 (`libpvxs`) and 339 (`libpvxsIoc`) findings, almost
   all `exported_not_public` template guard variables that are identical on
   both sides.

Together these would make an unchanged pull request produce an 844-finding
comment, 126 of them false. Both are fixes owed by abicheck, not by
suppressions here. This integration must not be enabled for anything beyond
shadow reporting until they are fixed.
