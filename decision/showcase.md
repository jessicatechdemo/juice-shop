# PR #16 Impact Showcase: Reject Forged JWTs for Authenticated APIs

## Summary

[PR #16](https://github.com/jessicatechdemo/juice-shop/pull/16) removes the `security.updateAuthenticatedUsers()` middleware from `server.ts`, which prevents forged JWTs (accepted only for challenge detection) from being cached and trusted by user-scoped APIs.

## Affected Challenges

This fix breaks the exploitability of the following OWASP Juice Shop challenges:

| Challenge | Key | Difficulty | Impact |
|-----------|-----|-----------|--------|
| **Unsigned JWT** | `jwtUnsignedChallenge` | ★★★★★ | Forged `alg:none` tokens no longer grant API access |
| **Forged Signed JWT** | `forgedSignedJwtChallenge` | ★★★★★★ | HMAC-signed-with-RSA-public-key tokens no longer grant API access |
| **View Basket** | `basketAccessChallenge` | ★★ | Forged tokens can no longer access other users' baskets |

## Test Evidence

### Before PR #16 (branch: `add-vul-back`) — Forged JWTs accepted

Test: `"GET basket should accept forged JWTs"`

```
▶ /rest/basket/:id
  ✔ GET existing basket by id is not allowed via public API (4.80ms)
  ✔ GET empty basket when requesting non-existing basket id (21.90ms)
  ✔ GET existing basket with contained products by id (10.91ms)
  ✔ GET basket should accept forged JWTs (8.32ms)       ← forged JWT returns 200
✔ /rest/basket/:id (397.01ms)
```

An unsigned `alg:none` JWT with arbitrary claims successfully accessed `/rest/basket/1` and returned **HTTP 200**.

### After PR #16 (branch: `codex/propose-fix-for-forged-jwt-vulnerability`) — Forged JWTs rejected

Test: `"GET basket should reject forged JWTs"`

```
▶ /rest/basket/:id
  ✔ GET existing basket by id is not allowed via public API (4.12ms)
  ✔ GET empty basket when requesting non-existing basket id (11.99ms)
  ✔ GET existing basket with contained products by id (11.50ms)
  ✔ GET basket should reject forged JWTs (1.73ms)        ← forged JWT returns 401
✔ /rest/basket/:id (384.00ms)
```

The same unsigned `alg:none` JWT now returns **HTTP 401 Unauthorized**.

## What Changed

**File:** `server.ts` (1 line removed)

```diff
  app.use(verify.jwtChallenges())
- app.use(security.updateAuthenticatedUsers())
  app.use('/rest/basket', security.isAuthorized(), security.appendUserId())
```

The `updateAuthenticatedUsers()` middleware was responsible for promoting tokens accepted by `jwtChallenges()` into the `authenticatedUsers.tokenMap`. Without it, forged tokens are still detected for challenge-solving purposes but cannot be used to authenticate against real API endpoints.

## Conclusion

Merging PR #16 closes the forged JWT impersonation vulnerability but renders the **Unsigned JWT** and **Forged Signed JWT** challenges unsolvable, since the exploit path (forged token → cached authentication → API access) is severed.

**Date tested:** 2026-08-07

Script to test
```
localStorage.setItem('token','eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.')        
location.reload()
fetch('/rest/basket/1', {                                                                                                                           
    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }                                                                         
  }).then(r => {                                                                                                                                    
                                                                                                                                                    
    console.log('Status:', r.status)                                                                                                                
    return r.json()                                                                                                                                 
                                                                                                                                                    
  }).then(data => console.log('Response:', data))   
```