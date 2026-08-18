# Distribution map

This is a discovery plan for `agent-egress-bench`, not a plan to create another
copy of the corpus. The corpus only means one thing when a result names the
same released bytes, schemas, and runner revision that another reader can
retrieve and verify.

## Non-negotiable rule for every surface

Any mirror must pin an upstream release tag and source commit. It can never
become a second canonical corpus. A mirror may contain a release archive or
link to one, but it must point consumers to the canonical GitHub repository,
the release tag, and the release identity and checksums. It must say, in the
first screen of its description, that GitHub is canonical and that the mirror
is a copy of the named release.

Consumers should accept a corpus copy only after the release verifier binds it
to that tag and source tree. The canonical release identity records the source
commit and hashes of the data bundle; the released schema catalog pins schema
bytes and retrieval URLs to that commit. [RELEASES.md](../RELEASES.md) and
[SCHEMAS.md](../SCHEMAS.md) define those checks. A surface that cannot retain a
specific release identity, or cannot label its bytes as a copy, does not fit.

## Ranked recommendations

### 1. Keep GitHub discovery surfaces accurate

**Fits: yes. Cost: low. Permanent obligation: review topics, description, and
homepage whenever the public scope changes.**

This is the highest discovery-to-maintenance ratio because GitHub already is
the canonical source. The repository currently has a short scope description,
a public homepage, Apache-2.0 metadata, and twelve relevant topics, including
`agent-security`, `ai-security`, `benchmark`, `mcp`, `dlp`, `prompt-injection`,
and `egress-security`. This is current repository metadata, checked on 2026-08-17.

Keep topics limited to the actual corpus scope: agent egress security, attack
corpus, benchmark, MCP, DLP, exfiltration, SSRF, and prompt injection. Do not
add product names, claims of coverage leadership, or tags that imply model
alignment testing. The README says those are outside scope. [README.md](../../README.md)

There is no mirror here. GitHub search leads to the canonical repository. The
repository description and README should continue to tell a consumer to cite a
release tag and run the release verifier, rather than fetch `main` for a
reproducible result.

### 2. Turn the existing citation file into release-based citation with Zenodo

**Fits: yes, after the first public release. Cost: low for setup, then a small
release checklist. Permanent obligation: every cited release must retain its
GitHub tag, release assets, release identity, and DOI metadata.**

Academic citability matters here. The repository already has a root
[`CITATION.cff`](../../CITATION.cff) that identifies this as a dataset, names
the author, declares the Apache-2.0 license, and points at the canonical
repository. `make preflight` already checks citation author identity, and the
release data bundle carries `CITATION.cff`. Those are current facts from the
repository.

Add a Zenodo GitHub integration only when there is a real release tag to
archive. GitHub currently reports no releases. At that point, publish the DOI
for the exact GitHub release and add the version DOI to the matching citation
metadata. Zenodo supports both `CITATION.cff` and `.zenodo.json`, but uses
`.zenodo.json` when both exist, so choose one metadata authority rather than
letting the two drift. [Zenodo software metadata guidance](https://help.zenodo.org/docs/github/describe-software/)
and [GitHub's citation-file documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-citation-files?apiVersion=2022-11-28)
support this flow.

Zenodo is an archive, not the corpus home. Its record must state `Mirror of
the canonical GitHub release <tag> at commit <sha>` and link back to the GitHub
release. Upload only the release assets that pass the repository verifier,
including the identity and checksum files. A paper should cite the version DOI
and release tag; a consumer should verify the archive against the canonical
tag as [RELEASES.md](../RELEASES.md) documents. Do not assign a DOI to a moving
branch or upload an unverified hand-built ZIP.

### 3. Use partner labs as release-pinned evaluation channels

**Fits: yes, selectively. Cost: medium. Permanent obligation: answer method
questions, preserve the release and artifacts behind every published result,
and correct any result that loses its method or release binding.**

The useful partner-lab ask is narrow: run a named release through their tool or
environment, publish the method and evidence, and link to the canonical
release. This creates independent use without giving anyone a mutable fork to
score against. It also matches the repository's policy that publishers own
their results and the corpus itself publishes no rankings. [GOVERNANCE.md](../GOVERNANCE.md)
and [RESULTS-USE.md](../RESULTS-USE.md) define that boundary.

Give a partner a release URL, tag, source commit, checksum file, release
identity, and the exact runner/profile instructions. Require the resulting
record to show all six and to label GitHub as canonical. If the partner needs a
hosted copy, it must be a frozen release archive with its SHA-256 recorded in
their report, never a synced branch or a locally amended fixture set. Decline
channels that cannot carry that identity or will present a copy as their own
dataset.

## Security and trust surfaces

### OpenSSF Scorecard: keep it, but do not chase a number

**Fits: yes. Cost: already paid for automation; ongoing cost is responding to
real repository-practice gaps. Permanent obligation: keep the workflow pinned,
eligible for authenticated publication, and honest about what the grade does
and does not measure.**

The repository already runs Scorecard on pushes to `main`, weekly, manual, and
branch-protection events. It uses digest-pinned checkout, Scorecard, and
artifact actions; withholds checkout credentials; grants only `contents: read`
and the `id-token: write` required to publish authenticated results; publishes
to the Scorecard API; and retains the SARIF artifact for five days.
[.github/workflows/scorecard.yaml](../../.github/workflows/scorecard.yaml)
is the source for those statements. The README already displays the public
Scorecard badge. Scorecard's own action says `publish_results: true` plus OIDC
publication enables the public API and badge. [Scorecard action documentation](https://github.com/ossf/scorecard-action)

Do not treat Scorecard as a corpus-quality badge. It rates repository hygiene,
not case validity, neutrality, or reproducibility. Keep it as a trust and
search signal, and fix findings when they improve the project, not to optimize
the displayed score.

### OpenSSF Best Practices badge: pursue passing after a short evidence audit

**Fits: yes at the passing level; defer silver and gold. Cost: medium for a
truthful self-assessment and policy evidence. Permanent obligation: keep every
attestation current as the project, maintainers, releases, and security process
change.**

The Best Practices badge is a separate, self-certified questionnaire. It is
not produced by Scorecard. The existing Scorecard workflow helps with some
evidence but does not establish a Best Practices tier. That distinction is
documented by OpenSSF. [Best Practices Badge criteria](https://github.com/coreinfrastructure/best-practices-badge)

Before applying for passing, audit the release process, issue and vulnerability
response policy, contribution guidance, automated tests, static analysis, and
the repository's public security documentation against the live questionnaire.
The release workflow already runs `make preflight` before producing tagged
assets, creates provenance attestations, and publishes draft releases only
after its gates pass. That is useful evidence, not a tier claim.

Silver would add durable people and process commitments: documented governance,
a succession or access plan, at least two people with necessary access, written
security requirements and an assurance case, dependency monitoring, 80%+
statement coverage, signed widespread-use releases, input validation, and
hardening. Gold then requires at least two unassociated significant
contributors, 2FA, majority review of modifications, reproducible builds, 90%+
statement coverage, 80%+ branch coverage, hardened sites, and a security
review. The exact criteria can change, so recheck the live questionnaire before
claiming a tier. These requirements come from OpenSSF's published higher-level
criteria summary. [OpenSSF criteria summary](https://github.com/coreinfrastructure/best-practices-badge)

The release verifier and immutable case policy already make the project a
better candidate than a typical code-only repository. The missing question is
whether it can honestly maintain the people, coverage, review, and response
promises. Do not apply for silver or gold as a visibility project.

