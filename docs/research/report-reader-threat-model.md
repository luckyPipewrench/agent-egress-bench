# Buyer report reader threat model

Decision record for BENCH-046. Reviewed against `origin/main` at `d537429` on 2026-08-17.

## Recommendation

**CLOSE BENCH-046 as out of scope.** Don't add the Windows `CreateFile` reparse-point open for the current buyer-report reader.

The reader is a renderer and an internal-consistency checker for a directory the caller selected. It doesn't execute a run or recalculate scores ([`docs/RUNNER.md:281-308`](../RUNNER.md#L281-L308)). The report itself says that all inputs to its checks, including the digests, come from the supplied directory; an edited directory can therefore reconcile with itself, and the reader doesn't authenticate it against anything outside that directory ([`runner/report.go:717-724`](../../runner/report.go#L717-L724)). That's the right boundary for a convenience report. It can't establish custody of a mutable directory.

The Windows race matters only after a party can both modify the selected directory during the read and influence a conclusion a different party relies on. In the supported model today, that party already has simpler ways to replace the conclusion or deny the reader a usable input. A platform-specific syscall boundary would close one narrow swap while leaving those direct attacks unchanged.

## What the reader guarantees

`--report` takes an existing artifact directory and returns before the normal run path ([`runner/main.go:52-53`](../../runner/main.go#L52-L53), [`runner/main.go:87-92`](../../runner/main.go#L87-L92)). It reads selected retained artifacts, checks declared digests and cross-file bindings, and renders missing, malformed, partial, blocked, and ineligible states visibly ([`docs/RUNNER.md:295-310`](../RUNNER.md#L295-L310)).

For an individual artifact read, the code creates an `os.Root`, does a root-relative `Lstat`, opens the name through that root, then checks the descriptor type and size ([`runner/report.go:180-249`](../../runner/report.go#L180-L249)). On Windows and the other non-POSIX targets, the extra open flags are zero; the code relies on `os.Root` confinement plus the pre-open `Lstat` and post-open descriptor check ([`runner/report_open_flags_other.go:1-24`](../../runner/report_open_flags_other.go#L1-L24)). That leaves the known window where a writer can replace a regular entry with a reparse point between `Lstat` and `OpenFile`.

Plain-language Windows guarantee: the report tries to keep each artifact read inside the directory resolved for that open and rejects bad data it observes. It doesn't provide a race-free snapshot of a writable directory, and it doesn't prove that the directory came from the claimed run or stayed unchanged. Treat a report rendered from a directory another party can still edit as a convenience view, not proof of custody.

## Cheaper attacks already available to this writer

The following are inferences from the documented boundary and the implementation. They don't require a Windows reparse-point race.

- Replace the whole retained packet with a self-consistent packet. The reader hashes evidence against digest values supplied by the same directory, and its own rendered warning says a whole-directory edit can still reconcile ([`runner/report.go:717-724`](../../runner/report.go#L717-L724), [`runner/report.go:827-914`](../../runner/report.go#L827-L914)). A writer can substitute an older run, a run for another configuration, or newly authored artifacts with matching digest fields before the report starts.
- Delete or corrupt an artifact. The reader renders such inputs as absent, invalid, or unreadable, and a directory with no usable run fact is refused ([`runner/report.go:118-157`](../../runner/report.go#L118-L157), [`docs/RUNNER.md:306-308`](../RUNNER.md#L306-L308)). This is a direct availability attack, with no timing window.
- Overwrite the generated Markdown after rendering when the output is stored in the writable packet. The release guide writes `artifacts/report.md` beside the inputs ([`docs/RELEASES.md:79-95`](../RELEASES.md#L79-L95)), and the renderer writes the chosen output path with `os.WriteFile` ([`runner/report.go:85-99`](../../runner/report.go#L85-L99)). A directory writer can replace that file after the reader exits.

The public-result policy already draws this distinction. `artifact-validated` means the result, manifest, digests, and declared bindings reconcile; it says nothing about who executed the run or when. `independently executed` requires a separate operator to control the execution host and retain the artifacts ([`docs/RESULTS-USE.md:26-39`](../RESULTS-USE.md#L26-L39)). A public result must also carry raw evidence and a verification path; a paid or buyer-facing report can't gate that evidence ([`docs/RESULTS-USE.md:62-66`](../RESULTS-USE.md#L62-L66)).

## Strongest case for building it

The strongest argument against closing this row is that the release build distributes the runner for Windows, so this isn't a dead target ([`.goreleaser.yaml:8-25`](../../.goreleaser.yaml#L8-L25)). The buyer report is intended for publication, with redaction because its retained command can contain credentials or local details ([`runner/redact.go:8-18`](../../runner/redact.go#L8-L18)). A buyer could plausibly render vendor-supplied artifacts on a shared Windows host, or a CI system could render an artifact directory after another job writes it. In that setup, a reparse-point swap could make a report cite a different regular file while still looking like an ordinary read.

That would be hard to defend if the report claimed to establish evidence custody. The project takes evidence integrity seriously: published results must retain raw evidence, normalized decisions, and a verification path ([`docs/RESULTS-USE.md:62-66`](../RESULTS-USE.md#L62-L66)); the first-party publication path then retains a hashed manifest and fails closed when the committed record or digest doesn't match ([`docs/CONTINUOUS-RESULTS.md:18-36`](../CONTINUOUS-RESULTS.md#L18-L36)). The current buyer report doesn't make that stronger claim. Its self-consistency wording is explicit about the limit, so closing this residual doesn't hide the gap.

The static scan found no repository-managed CI invocation of `--report`; that's an inference from `.github`, `scripts`, examples, and documentation at `d537429`, not proof that no downstream user runs it in CI. The documented examples instead have the operator render a retained local directory ([`examples/operator-kit/README.md:40-48`](../../examples/operator-kit/README.md#L40-L48)).

## Trigger that reopens the decision

Reopen BENCH-046 when a **cross-principal mutable-bundle reader** becomes a supported flow: one party can write an artifact directory after a separate trust event, another party renders it on Windows, and that report contributes to a decision or published result. The proposal must also show why the packet is protected from the three simpler attacks above, for example by copying it into a read-only custody location and binding it to a signature or trusted digest before the writer can alter it.

At that point, build and test the Windows fix as part of the whole trust boundary. The test must run on Windows, repeatedly swap a regular artifact for a reparse point during the exact report open, and prove that the reader refuses it without reading the replacement. It must also test the ordinary Windows path and a retained, read-only packet, because a fix that blocks normal archive extraction or ordinary report generation would weaken adoption and invite operators to bypass it. The implementation choice should be reconsidered then, including the lifetime of the root directory handle, rather than assuming a direct syscall alone solves the new flow.

## Scope correction

The current code doesn't hold one `os.Root` for the full report. `loadBuyerReport` calls separate readers for each named artifact, while `openRegularArtifact` opens and closes a root for each reader call ([`runner/report.go:111-117`](../../runner/report.go#L111-L117), [`runner/report.go:180-186`](../../runner/report.go#L180-L186)). This doesn't change the out-of-scope decision: a writer with that directory already has the non-racing substitution, replay, denial, and output-overwrite paths above. It does mean the PR #193 description of all lookups happening beneath one held root shouldn't become a buyer-facing guarantee until the implementation holds that root across the report.

## Adjacent findings for CC to evaluate

- [`runner/report.go:111-117`](../../runner/report.go#L111-L117) and [`runner/report.go:180-186`](../../runner/report.go#L180-L186): the reader creates a fresh root per artifact rather than retaining one root for the report. Check the PR #193 wording and decide whether a future hardening pass needs a single root lifetime.
- [`docs/RELEASES.md:90`](../RELEASES.md#L90) and [`runner/report.go:85-99`](../../runner/report.go#L85-L99): the documented release flow writes `report.md` into the directory it reads. If a future cross-principal flow makes that directory untrusted, write the output into a separate trusted location or bind the output before anyone relies on it.
