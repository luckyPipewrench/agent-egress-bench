# Result pointers

This directory lists pointers at evidence some other publisher hosts.

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
pointer pull request. To withdraw a listing, add a `withdrawn` object. Do not
delete history to hide a miss. Withdrawal keeps the filename and the original
evidence identity.

`report_family` names the kind of packet the URL holds. It is not a grade.
Allowed values live in the schema.
