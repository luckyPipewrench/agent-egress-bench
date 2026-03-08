## What

One sentence: what does this PR add or change?

## Why

Why is this needed?

## Checklist

- [ ] Cases validate: `cd validate && go build -o /tmp/aeb-validate . && /tmp/aeb-validate ../cases`
- [ ] All secrets are obviously fake
- [ ] Case IDs match filenames
- [ ] New cases include `description`, `why_expected`, `false_positive_risk`, and `source`
- [ ] Benign cases have `"safe_example": true`
