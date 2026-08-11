# Control Evidence v1 conformance vectors

These seven directory packages exercise the v1 verifier through its public
package loader. They cover every result outcome and both fresh and repeated
verification. Package directories contain only signed payloads and
manifest-bound raw artifacts. `contexts/` and `expectations/` hold the
independent verifier inputs and test assertions outside the package boundary.

The verifier does not read the expectation sidecar. The corpus test supplies it
as the assertion and creates a private replay ledger when the vector requires
durable state.

Regenerate or verify the committed bytes from the generator directory:

```sh
cd control-evidence/v1/conformance/_generator
go run . --write
go run . --verify
```

The generator derives synthetic material from the frozen v0 golden package,
upgrades every versioned payload, signs it again, and rebuilds the manifest. It
does not share code with the verifier.
