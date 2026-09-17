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

`.ci-local/abicheck-components.json` declares the two components by pattern.
Resolving those patterns — picking the real shared object out of its SONAME
alias chain, checking it is an ELF `ET_DYN`, agreeing the target machine
between components, expanding the owned header sets and refusing a stale
exclusion — belongs to abicheck's `actions/baseline` (`library-spec`), not to
PVXS.

Two assertions the declaration makes deliberately, because a glob alone would
lose them:

* `include/pvxs/versionNum.h` is named explicitly as well as matched by the
  `*.h` glob. A header pattern that matches nothing is a hard error, so a
  build that did not generate it fails the capture instead of quietly
  producing a 14-header surface in which every `versionNum` declaration reads
  as removed.
* `header_exclude: include/pvxs/iochooks.h` is likewise an error if it matches
  nothing, so if that header is ever renamed or moved, `libpvxs` cannot
  silently re-acquire its sibling's declarations.

What is left in `.github/actions/abicheck-capture` is PVXS's own build-system
knowledge and nothing else: where `cue.py` recorded `EPICS_BASE`, which
`EPICS_HOST_ARCH` it built for, the native-Linux guard, and rendering those
two values into the declaration.

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

Selection by base SHA alone is not sufficient, so an accepted-main
baseline must additionally come from this repository's own
`ci-scripts-build.yml`, from a push to the pull request's base branch, and
from a run that **concluded success**. Without the last two, a failed run's
snapshot could become the baseline — the capture step deliberately still
runs after a test failure. That eligibility decision is
`actions/verify-baseline-source` (`mode: producer-run`), which also prints
every candidate it rejected and why, so "no eligible baseline" can say what
it did see. "No eligible run", "the lookup failed" and "the artifact
expired" remain three different outcomes; PVXS only fetches the bytes once
the verifier reports `eligible`.

Tag identity for the release channel is the same Action in `mode: tag`. It
resolves `refs/tags/<name>` explicitly rather than the commits endpoint
(which would happily resolve a branch), peels an annotated tag, assumes no
`v` prefix — PVXS tags are bare versions like `1.5.2` — and requires the tag
to name the exact commit that was built.

A missing, expired, wrong-profile or incompatible baseline produces an
explicit unavailable/incomplete outcome. It never produces a clean result.

### What the baseline publisher refuses

`.github/actions/abicheck-publish-baseline` validates a set before any of
it is staged or uploaded. It checks the manifest's `profile`, that both
components are present, and that the manifest's `project_ref` is the commit
the requested tag actually names — resolving `refs/tags/<name>` explicitly
rather than through the commits endpoint (which would resolve a branch of
the same name) and peeling an annotated tag rather than accepting the tag
object's own sha.

The revision check exists because nothing downstream repeats it. The
accepted-main comparisons pass `expected-project-ref` to `check-target`,
since a pull request knows exactly which commit its baseline must describe.
The release-contract comparisons cannot, because the release is chosen at
consumption time — so they deliberately pass no expected ref. The publisher
is therefore the only point where a set claiming the wrong revision can be
caught, on either publishing path.

That matters most for the bootstrap below, which runs a historical
revision's own build system in the shared workspace before the runner loads
the capture action. Splitting the jobs put the write token out of that
code's reach; it did not make the artifact it produces trustworthy. The
claim is verified where both paths converge rather than trusted from the
producer.

### Bootstrapping a historical release

A release that predates this integration has no capture, and re-dispatching
the old workflow cannot produce one — the workflow *at that tag* has no
capture step. `abicheck-baseline.yml`'s `workflow_dispatch` path therefore
builds the requested revision once, in the trusted default-branch workflow,
captures it with the same shared action and the same component declaration
the matrix leg uses, and publishes the result. It is a one-time operation
per release and never runs on a pull request.

That path is **two jobs, deliberately**. The build job runs the requested
revision's own code — its `cue.py`, its submodules, its makefiles — and so
holds `contents: read` and nothing else. It hands the captured baseline-set
to the second job as an artifact. The publishing job holds `contents:
write` but executes none of that code: it consumes the artifact and
nothing else.

"Checks out the default branch" is enforced, not assumed. `workflow_dispatch`
runs from whichever ref was selected, and a checkout with no `ref:` takes
*that* ref — so the publishing job both refuses to run unless `github.ref`
is the default branch, and names the default branch explicitly in its
checkout. Without that, dispatching from any branch would load
`./.github/actions/abicheck-publish-baseline` from that branch into the job
holding `contents: write` and `github.token`.

The build job is deliberately left unrestricted: it is read-only, so
dispatching it from a branch to exercise the capture is safe, and the
publish job simply does not run.

Without the split, historical code could overwrite
`.github/actions/abicheck-publish-baseline` in the shared workspace before
the runner loads it, and that local action is handed `github.token`.
`persist-credentials: false` does not prevent that — it stops the historical
checkout receiving credentials, not a later step loading a tampered local
action.

The component declaration is read from the default-branch checkout, not
from the historical tree, which predates the file entirely.

## Publication

`.github/workflows/abicheck-report.yml` is a separate, trusted publisher:

* The analysis workflow has `contents: read` and no secrets. It is never
  given write access to make a comment work, and contributor code is never
  run under `pull_request_target`.
* The publisher runs from the default branch on `workflow_run`, with only
  `actions: read` and `pull-requests: write`.
* It delegates to two reviewed abicheck Actions rather than growing its own
  logic: `actions/verify-source-run` establishes which run this is, which
  pull request it belongs to and which commit was actually analysed — all
  from the GitHub API, never from the artifact — and extracts the artifact
  under size, entry-count and compression-ratio caps;
  `actions/report` renders the producer's canonical aggregate document and
  maintains the sticky comment.
* The pull request head SHA and the commit that was actually analysed are
  separate coordinates. For a `pull_request` producer the analysed commit
  is the ephemeral merge commit, not the PR head, and the comment shows the
  analysed one. They are never substituted for each other.
* Publication is bound to the producer attempt that triggered it, and
  concurrency is keyed per pull request and profile. The sticky comment's
  ordering guard is given the *producer's* run id and attempt, not the
  publisher's: ordering by the publisher would let a late re-run of an
  older commit overwrite a newer result.
* It never checks out, installs, imports or executes pull-request code or
  pull-request-built binaries, and it runs no analysis.
* A publication failure fails visibly and is never reported as a clean
  compatibility result. A compatibility verdict never fails the publisher.

A trusted reporter does not make contributor-produced report contents trusted
evidence. Origin and assurance are preserved; what is enforced is who the
result is delivered to and what executes while delivering it.

**Deployment prerequisite:** `workflow_run` only ever runs the copy of the
publisher on the default branch. Until a maintainer merges it there, no pull
request — including the one introducing it — will publish a comment.

## Incomplete analyses

There is one document shape, not two. When no candidate capture exists, or
a comparison did not run, the expected checks are still declared and
`abicheck aggregate` produces an aggregate document in which those targets
are `unavailable`. That is the same shape the publisher reads on the happy
path, so a producer failure cannot arrive at the publisher as a file it
does not understand. `actions/aggregate` validates the document before it is
handed downstream and separates the axes: `compatibility-exit` carries
`abicheck aggregate`'s own 0/1/2/4 without failing the step, which is what
keeps this gate advisory, while a refused declaration, a usage error or a
document that does not describe a real outcome fails the step. Operational
loss cannot reach the publisher disguised as an empty finding set.

A report that ran and produced garbage is tracked as `unusable`, separately
from one that never ran at all. Both stay declared expected, so one
component's failure never costs the others their diagnostics, and `channels`
splits the roll-up per baseline channel — "the release comparison is
missing" is distinguishable from "one component is missing".

Only the checks an event actually has are declared: the accepted-main
comparisons exist on a pull request, not on a push or tag build.

## Gate policy

Advisory (`gate-mode: advisory`) during shadow adoption. Gate status and
compatibility are reported separately: the check can be green while
prominently reporting a detected break. ABICC remains authoritative.

## What has actually been compared

Two different questions, kept apart on purpose: what this branch's **CI** has
analysed, and what has been **measured locally** on real builds.

### In CI: nothing yet, and the green advisory check does not say otherwise

Every run of this branch reports `status=fail coverage=empty,
0/4 target(s) analyzed`, `channels: {accepted-main: {analyzed: 0,
unavailable: 2}, release-contract: {analyzed: 0, unavailable: 2}}`. The job
concludes success because the gate is advisory and operational loss is
reported as loss. Since this branch also renders that state into the job
summary, a reader no longer has to open `aggregate.json` to discover it:

```
ABI/API comparison not performed: 0/4 checks completed.
Baselines unavailable; no compatibility verdict was produced.
```

Both channels are unavailable for reasons this pull request cannot fix, and
one of them is structural rather than transient:

| Channel | Why unavailable | What would change it |
|---|---|---|
| accepted-main | The pull request's base commit `b5024df` is on `master`, whose `ci-scripts-build.yml` contains **no abicheck integration at all** — so no push run of that revision ever produced, or could produce, a candidate artifact. `verify-baseline-source` additionally refuses master's one run by name (`rejected run 35112205613: wrong-conclusion: the source run concluded 'failure'`), but fixing that run would not help: the artifact it would need does not exist in that revision's workflow. | This integration reaching the default branch, after which the base commit of the next pull request has a real capture. |
| release-contract | The fork has tags (`1.5.2`, `1.5.1`, …) but **zero GitHub Releases**, so there is no release to carry an asset and nothing for `resolve-baseline` to fetch. | An authorized one-time bootstrap: create the release for the selected tag, then dispatch `abicheck-baseline.yml` for it. |

Neither is worked around. No baseline is fabricated, no comparison is
quietly skipped, and the missing coverage is reported as missing.

### Locally: four real comparisons, on real builds

To show the comparison path actually works — rather than only that the
plumbing is wired — all three revisions were built and captured with the
same declaration and the same pinned toolchain CI selects (CastXML
`0.6.20260105-g9864b1e`, bundled Clang `21.1.8`, GCC 13.3.0, EPICS Base 7.0,
bundled libevent at the identical submodule commit in all three revisions,
so the profile really is constant).

| Check | Old side | Verdict | Gating | Public +/−/mod |
|---|---|---|---|---|
| libpvxs vs accepted-main | base `b5024df` | **COMPATIBLE** | 0 | 0 / 0 / 0 |
| libpvxsIoc vs accepted-main | base `b5024df` | **COMPATIBLE** | 0 | 0 / 0 / 0 |
| libpvxs vs release-contract | tag `1.5.2` (`8e00eae`) | **BREAKING** | 2 | 1 / 2 / 0 |
| libpvxsIoc vs release-contract | tag `1.5.2` (`8e00eae`) | **COMPATIBLE** | 0 | 0 / 0 / 0 |

**The two channels disagree, and that is the point.** Against its own base
this pull request introduces nothing — as it should, since it changes no
runtime source. Against release 1.5.2 `libpvxs` is breaking, because two
weak typeinfo symbols for a lambda inside
`SharedPV::Impl::connectSub(...)` are present in 1.5.2 and gone afterwards.
That was confirmed independently of abicheck with `nm -D`: both symbols are
in 1.5.2's binary and absent from **both** the base and the head binary — so
the removal happened somewhere between 1.5.2 and `master`, and is not this
pull request's doing. A release-relative finding is drift since the release,
never automatically a change this pull request introduced.

### Controls

| Control | Result |
|---|---|
| Independent rebuild, same revision | COMPATIBLE, 0 gating, 100% binary compatibility |
| Disposable public break (`testAfterShutdown()` removed from the binary) | detected `func_removed`, severity `breaking`, `artifact_proven`, gating 1, exit 4 |
| Disposable compatible addition (`abicheckProbe(long)`) | detected `func_added`, severity `compatible`, non-gating |
| Snapshot independence | comparison succeeded in 1s after the source and install trees were deleted, with no re-extraction |
| Test mutations in shared source | none: the controls lived in a throwaway worktree, and `HEAD` still declares `testAfterShutdown()` and knows nothing of `abicheckProbe` |

The break control also produced an unplanned `exported_not_public` finding
for the helper the control renamed, which is the tool correctly objecting to
a symbol exported without a public declaration.

### What the risk-change counts actually mean

Every comparison above also reports 339–517 non-gating `risk` changes. The
independent-rebuild control puts a number on how much of that is signal:
rebuilding **the same revision** and comparing it against itself still
produces **339** risk changes for `libpvxsIoc`. That is the noise floor of
the known upstream attribution defect (dependency and sibling symbols
attributed to the component), not change. It is why this integration stays
advisory, and why those counts are reported but not gated.

### Measured separately

| Stage | Time |
|---|---|
| Build (per revision, EPICS Base and libevent already present) | 46–50 s |
| Capture `libpvxs` (15 headers, ~120 MB snapshot) | 67 s |
| Capture `libpvxsIoc` (1 header, ~2.3 MB snapshot) | 7 s |
| Compare `libpvxs` | 131–133 s |
| Compare `libpvxsIoc` | 2 s |
| Compare from snapshots after the trees were deleted | 1 s |

The abicheck job's earlier ≈1-minute wall time is not a comparison
benchmark: that job performed **zero** comparisons. Snapshot compression
changes stored bytes, not extraction time.

### A measurement error worth recording

The first run of this exercise reported `libpvxsIoc` **BREAKING against its
own base**, which is impossible for a pull request that changes no runtime
source. The cause was not the tool: the shared checkout's *installed*
`include/` tree (a gitignored build output) still held an earlier session's
disposable controls — `testAfterShutdown()` deleted and `abicheckProbe(long)`
added — while its source and binary were clean. The candidate snapshot was
therefore taken from a stale, mutated install tree.

The finding was real for the inputs given; the inputs were wrong. Every
number above was re-measured from freshly built worktrees, and the stale
install tree has been refreshed. The git source was never affected. This is
the concrete reason capture must be pinned to the build that produced it
rather than to whatever happens to be lying in an install directory.

## Dependency status

Every abicheck Action is pinned to one merged, immutable revision:
`80cf72abb5856eb623a6056fb35d06a66ad26774` on abicheck `main`. It carries
[#1315](https://github.com/abicheck/abicheck/pull/1315) (`actions/aggregate`,
`actions/verify-baseline-source`, `library-spec` resolution) on top of
[#1311](https://github.com/abicheck/abicheck/pull/1311) (report-only
publication and the aggregate-shaped PR comment), plus
[#1319](https://github.com/abicheck/abicheck/pull/1319). Nothing here depends
on an unmerged revision, a mutable branch, or a placeholder ref.

**#1319 is why this pin moved, and it fixed a live defect here.** At the
previous pin, `actions/report` declared and documented `source-run-id` /
`source-run-attempt`, and its `run.sh` read `INPUT_SOURCE_RUN_ID` — but
`action.yml` never forwarded the inputs into the step's environment. The
values this workflow passes were therefore discarded, and the ordering guard
silently fell back to `GITHUB_RUN_ID`: the *publisher's* run, which orders by
when publication was triggered rather than when the analysis ran. That is the
precise inversion the guard exists to prevent, and it is what the caller here
was written to avoid. The guard was inert until this pin.

The one local composite Action that remains for a generic reason is
`.github/actions/abicheck-publish-baseline`.

abicheck [#1319](https://github.com/abicheck/abicheck/pull/1319) added the
replacement this was waiting for — `publish-baseline.yml` now takes
`baseline-set-artifact-prefix` and will publish an already-captured
baseline-set, validating it against the profile, release tag and generation
it is being published as. That is strictly stronger than the local action.

It does not yet fit **both** of this integration's publication paths, and
adopting it for one would leave two publishers, which is the duplication
this integration exists to remove:

| Path | Where the set lives | Fits upstream? |
|---|---|---|
| Bootstrap (`workflow_dispatch`) | artifact in the *same* run, from `bootstrap-build` | **yes** |
| Tag publication (`workflow_run`) | artifact in the *producing* run | **no** |

The blocker is one input, and it is unchanged as of abicheck `main`
(`db3b12c`): `publish-baseline.yml` downloads the set with
`actions/download-artifact` using `pattern:`/`name:` alone, with no `run-id`
and no token, so it can only see artifacts of the run it is executing in.
Re-checked at both this pin and `main` — `actions/` and
`publish-baseline.yml` are byte-identical between the two, so there is
nothing newer to adopt and no reason to move the pin for it. A `workflow_run`
publisher is by construction a *different* run from the one that captured
the set — that separation is the security boundary, not an accident, so
moving the capture into the publishing run is not an option.

What would close it: a `run-id` (and token) passthrough on the pre-captured
path, or the ability to hand the workflow an already-downloaded directory.
Either would let both paths use one publisher and retire this action. That
is the remaining upstream dependency; it is not worked around here.

## Known issues (abicheck product bugs, re-measured 2026-09-16 on `0b50f80`)

Re-measured on this branch with abicheck
`0b50f807c8ea05719e414e78564c31ef32a2ea4e` and CastXML 0.7.0, by comparing
each component's snapshot against itself — a byte-identical pair, where the
only correct answer is "no change".

What the merged revision fixed: nothing these two produce now gates or is
presented as a change. Both self-comparisons return verdict `NO_CHANGE`
with `0` gating findings, and the rendered PR comment says so explicitly —
"♻️ 845 pre-existing cross-source hygiene findings present on both sides —
not introduced by this change", with an audit line reading `845 detected ·
0 gating · 845 non gating`.

What is still wrong, at the detection layer:

1. **Include-context headers are still charged to the component.** EPICS
   Base symbols (`epicsMutex::lock()`, `epicsEvent::wait()`, `errVerbose`,
   …) and libstdc++ internals still appear in `libpvxs`'s own itemized
   list, and `pvxs::version_str()`/`version_int()`/`version_abi_int()` —
   declared in `pvxs/version.h`, which `libpvxs` owns — appear in
   `libpvxsIoc`'s. All are reached only through `-I` include roots, not
   through the component's own declared public surface.
2. **Persistent hygiene findings are still detected on an unchanged pair.**
   An unchanged `libpvxs` detects 505 findings and `libpvxsIoc` 340, listed
   as 505 and 340 "Modifications" in the per-component review rendering,
   although both fold to zero gating findings.

So the effect on a pull-request comment is now bounded and honestly
labelled, but the underlying attribution is still wrong and the full
per-component report is still 845 items of noise. Both remain fixes owed by
abicheck, not by suppressions here. This integration stays advisory until
they are fixed.

### Capture flake worth watching

One `abicheck dump` invocation in this re-measurement failed with "CastXML
of unknown version was found", from the same CastXML 0.7.0 binary that a
`--version` probe and an immediately following dump both accepted. It has
been seen once and did not reproduce on retry. If a capture leg fails that
way in CI, it is this, not a real toolchain problem — but the leg fails
loudly rather than degrading to "no findings", which is the intended
behaviour.
