# Result pointers

This directory lists **pointers** at evidence some other publisher hosts.

A pointer is admitted when its object matches the closed v1 schema and, unless
it is withdrawn, the bytes at its HTTPS-port-443 `evidence_url` hash to
`evidence_sha256`.
Run `python3 scripts/validate_result_pointers.py` from a source checkout or
release data bundle to repeat that admission check.

**Listing is not approval.** It is not a rank, a mark, a badge, a certification,
or a claim that Agent Egress Bench ran or scored the product. Alphabetical
index order is not a ranking.

Do not put result JSONL, summaries, or scores in this repository. Submit a
pointer pull request. To withdraw a listing, add a `withdrawn` object with one
of `dead_url`, `publisher_request`, or `digest_mismatch`. Do not delete history
to hide a miss. Withdrawal preserves the entry's filename and every original
evidence field.

`report_family` is a label for the kind of packet the URL holds (`gauntlet`,
`pass-fail`, or `gateway-inspectable`). It is not a grade.
