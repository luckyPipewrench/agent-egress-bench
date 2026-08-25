# Result pointers

This directory lists pointers to evidence that another publisher hosts.

**Listing is not approval.** It is not a rank, a mark, a badge, a certification,
or a claim that Agent Egress Bench ran or scored the product. Alphabetical
index order is not a ranking.

Admission is mechanical. The closed schema is
[`schemas/result-pointer-v1.schema.json`](../schemas/result-pointer-v1.schema.json).
Unless a pointer is withdrawn, `python3 scripts/validate_result_pointers.py`
fetches the evidence over HTTPS port 443 and checks the digest. That check
runs at pull-request preflight. It is not a later availability guarantee.
A consumer that needs current bytes fetches and hashes them.

Do not put result JSONL, summaries, or scores in this repository. Submit a
pointer pull request. The admission checker fetches evidence only to hash it
and does not write those bytes into this repository.

The listing is append-only. Adding a pointer is allowed. An existing pointer
cannot be deleted, and its evidence identity cannot be rewritten. To withdraw a
listing, open a pull request that adds a `withdrawn` object. Withdrawal keeps
the filename and the original evidence identity. A vendor that wants a listing
removed uses `withdrawn.reason` `publisher_request`. The other closed reasons
are `dead_url` and `digest_mismatch`. Do not delete history to hide a miss.

`report_family` names the kind of packet the URL holds. It is not a grade.
Allowed values live in the schema.
