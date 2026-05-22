# Receipt Profiles

This directory is for maintainer-published receipt profiles described in
[`docs/RECEIPT-SCORING.md`](../docs/RECEIPT-SCORING.md).

A receipt profile records whether a tool produced the expected verdict,
explained it, emitted signed evidence, and made that evidence independently
verifiable. Profiles are evidence artifacts, not certifications or rankings.

Profile submissions should include reproduction steps either in the profile
itself or in a sibling `notes.md` file. The corpus maintainers review profile
shape, referenced case IDs, and verifier metadata; relying parties are still
expected to reproduce the profile before trusting it.
