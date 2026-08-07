# Juice Shop forged JWT impersonation validation

This directory contains two minimal PoCs for commit a7c127928ddacc5314cb41d5aa8825cc67c0835a.

* `poc_forged_jwt_api.sh` starts the built Juice Shop server, creates unsigned `alg:none` JWTs with arbitrary `data.id` claims, and calls real HTTP endpoints (`/api/Cards` and `/rest/basket/1`). In the validation container the application precondition checks fail because of Node/dependency mismatches, so the script uses a preload hook to stub the missing YAML schema module and prevent `process.exit(1)` after precondition failure; it does not patch the authentication middleware.
* `debug_trace_update_append.js` uses Node's built-in inspector to set breakpoints in `build/lib/insecurity.js` on the `jwt.verify`, `authenticatedUsers.put`, and `appendUserId` assignment lines. It invokes the actual middleware with a forged token and prints the cache transition and `req.body.UserId` assignment. `debug_trace_update_append.out` is a captured run.

If the build directory is stale, rebuild server JS first with:

```sh
npx tsc --ignoreDeprecations 6.0 || true
```

Then run:

```sh
JUICE_SHOP_DIR=/workspace/juice-shop bash /workspace/validation_artifacts/jwt-forged-impersonation/poc_forged_jwt_api.sh
node /workspace/validation_artifacts/jwt-forged-impersonation/debug_trace_update_append.js
```
