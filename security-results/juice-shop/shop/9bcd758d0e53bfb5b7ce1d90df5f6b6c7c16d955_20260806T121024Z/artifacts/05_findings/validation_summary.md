# Validation summary

| Candidate | Root control | Entrypoint | Sink | Disposition | Counterevidence or proof gap | Survives |
|---|---|---|---|---|---|---|
| routes-search-q-type-confusion | routes/search.ts:21 | Anonymous GET /rest/products/search | routes/search.ts:22-23 | reportable | Errors are likely request-scoped and amplification is bounded; application execution was forbidden, so sustained availability impact is unmeasured. | yes |
