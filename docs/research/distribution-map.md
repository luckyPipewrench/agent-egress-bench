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

The Best Practices badge is a separate, self-certified questionnaire. It is <!-- claim-ok: describes the OpenSSF questionnaire, not a Gauntlet claim -->
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
whether it can maintain the people, coverage, review, and response
promises. Do not apply for silver or gold as a visibility project.

## Surfaces that are not worth doing now

### Hugging Face datasets

**Fits: no, for the present project shape. Cost if forced: medium to high.
Permanent obligation: reproduce every canonical release as a complete,
release-verified dataset revision, retain its upstream tag and commit, and
support users who fetched the wrong Hub revision.**

Hugging Face can pin a dataset fetch to a commit, tag, or branch revision. That
technical capability does not make a second dataset repository a good home for
this corpus. The benchmark needs the cases, schemas, contracts, runner, and
release identity together. A data-only card would encourage consumers to fetch
cases without the runner or release verifier. A full release archive would
duplicate what the canonical GitHub release and a Zenodo archive already
provide, with another revision history to keep correct. Hugging Face documents
revision pinning, but its normal dataset interface also makes a moving default
revision easy to consume. [Hugging Face dataset versioning](https://huggingface.co/docs/datasets/v1.7.0/share_dataset.html)

Do not create a Hub mirror. Reconsider only if researchers demonstrate that
Hub discovery materially reaches the right users and will accept a
release-archive-only record. That record would need a tag named for the
upstream GitHub release, the exact upstream commit and SHA-256 in its card, and
the unmodified verified release bundle. Its first paragraph would identify
GitHub as canonical and send users to the release verifier. Without all of
that, the surface fails the non-negotiable rule.

### Kaggle

**Fits: no. Cost if forced: high. Permanent obligation: publish and describe a
new Kaggle version for every canonical release, preserve its correspondence to
the GitHub release, and prevent consumers from treating Kaggle's latest
version as the benchmark definition.**

Kaggle offers dataset versions, but its workflow is built around creating a
new version from uploaded files and version notes. That is suitable for data
analysis, not for a corpus whose result needs to bind runner, contracts, and
source commit. [Kaggle CLI dataset-version documentation](https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets.md)
confirms the per-upload version model.

The maintenance burden would duplicate release publication without adding a
reproducibility property GitHub releases and Zenodo lack. A Kaggle record
cannot be an independent canonical corpus. Do not create one. If a future
competition requires it, upload only an immutable canonical release archive,
name the Kaggle version after the GitHub tag, record the source commit and
checksum in the description, and link back to the canonical release. Never
upload a case directory by itself.

### Security-corpus catalogs

**Fits: metadata-only listings can fit; a hosted duplicate does not. Cost:
low per listing, but medium if the catalog asks for an ongoing hosted copy.
Permanent obligation: keep a listing's scope, canonical URL, release policy,
and contact route accurate.**

There is no obvious broad catalog whose scope exactly matches agent egress
security. NIST's CFReDS catalog is a digital-forensics dataset collection, and
NIST SAMATE focuses on known-bug programs and tool effectiveness. They are
useful precedents, not destinations for this corpus. [CFReDS](https://cfreds.nist.gov/all/)
and [SAMATE](https://www.nist.gov/itl/csd/secure-systems-and-applications/samate)
describe their own scopes.

Submit a metadata-only entry to a credible agent-security or security-evaluation
catalog if one accepts a canonical URL rather than corpus hosting. The entry
must link to a named GitHub release, state its commit and release identity,
label GitHub canonical, and say that the catalog has no authority to alter or
republish cases. Reject any catalog that only offers a mutable uploaded copy.
This is an inference from the corpus's release and immutability rules, not a
claim about a particular catalog's policy.

### Package managers

**Fits: no package-manager distribution for the corpus itself. Cost if forced:
high. Permanent obligation: define and preserve a package API, publishing
namespace, release semantics, support policy, and security-update path that do
not exist today.**

The repository is a corpus plus a runner, rather than a library for another
program to import. It already defines a better installation boundary: tagged
releases provide a data bundle, platform archives with both executables,
checksums, a release identity, and a digest-pinned OCI runner image.
[RELEASES.md](../RELEASES.md) is the contract for that boundary. Publishing a
thin PyPI, npm, Homebrew, or Go package would make the project look like an API
dependency and create version-pressure unrelated to corpus releases.

Keep release assets and the digest-pinned runner image as the supported
delivery methods. If a package manager becomes necessary for a small client in
the future, ship only a downloader that requires an explicit canonical release
tag, verifies checksums and release identity, and never embeds a mutable case
snapshot. That is an inference, not a present recommendation.

### Conference and standards directories

**Fits: a paper or metadata submission that links to a tagged release can fit;
an evergreen directory or standards listing is not a current priority. Cost:
medium to high. Permanent obligation: maintain the cited artifact, answer
review questions, and keep claims inside the corpus's tool-neutral scope.**

Do not treat a conference directory as a distribution channel that needs a
live appearance. If a venue offers a dataset or benchmark artifact track,
submit the release DOI, GitHub tag, source commit, and release-verification
instructions. The artifact itself must say it is a copy of the canonical
release. Do not submit a moving repository URL as the benchmark definition.

The repository already maps its case categories to the OWASP Agentic Top 10,
and the README's check keeps that table in sync with the corpus. That is a
scope mapping, not an OWASP endorsement or standards certification. <!-- claim-ok: states the non-claim -->
[README.md](../../README.md) is the current source. Avoid directories that
would turn that mapping into an implied certification, or that require the <!-- claim-ok: warns against implying one -->
corpus to follow a mutable external taxonomy as its canonical contract.

## Recommended order of work

1. Keep GitHub topics, description, homepage, and Scorecard publishing healthy.
2. Cut and verify the first release, then connect Zenodo and add a version DOI
   to the citation path.
3. Offer that frozen release to a small number of partner labs and
   metadata-only catalogs that agree to the canonical-source rule.
4. Assess the OpenSSF Best Practices passing questionnaire with evidence.

Do not start Hugging Face, Kaggle, package-manager, or generic
conference-directory work unless a named consumer need proves the discovery
gain. Their maintenance can create enough copies and versions to weaken the
benchmark's reason for existing.

## Evidence and inference boundary

Claims about repository state in this document were checked against
`origin/main` at `d537429e3bec0e7e1a35c803db1570af42eae52a` on 2026-08-17,
the repository metadata, and GitHub's release list. Recommendations about
future channels are marked as recommendations or inferences. External service
rules should be rechecked before an implementation decision because they can
change.
