import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { globToRegExp, parseManifest, sideOf } from '../src/manifest.ts';

describe('globToRegExp', () => {
  it('supports *, ** and ?', () => {
    assert.ok(globToRegExp('server/*.lua').test('server/main.lua'));
    assert.ok(!globToRegExp('server/*.lua').test('server/sub/main.lua'));
    assert.ok(globToRegExp('server/**/*.lua').test('server/main.lua'));
    assert.ok(globToRegExp('server/**/*.lua').test('server/a/b/main.lua'));
    assert.ok(globToRegExp('cl_?.lua').test('cl_1.lua'));
    assert.ok(!globToRegExp('a.lua').test('aXlua'));
  });
});

describe('parseManifest', () => {
  const manifest = parseManifest(`
fx_version 'cerulean'
game 'gta5'
shared_script '@ox_lib/init.lua'
shared_scripts { 'config.lua' }
client_scripts {
  'client/*.lua',
}
server_script "server/main.lua"
server_scripts({ '@oxmysql/lib/MySQL.lua', 'server/modules/**/*.lua' })
-- server_script 'commented.lua'
`);

  it('collects script globs per side and skips external references', () => {
    assert.equal(manifest.server.length, 2);
    assert.equal(manifest.client.length, 1);
    assert.equal(manifest.shared.length, 1);
  });

  it('resolves the side of a file', () => {
    assert.equal(sideOf(manifest, 'server/main.lua'), 'server');
    assert.equal(sideOf(manifest, 'server/modules/a/b.lua'), 'server');
    assert.equal(sideOf(manifest, 'client/main.lua'), 'client');
    assert.equal(sideOf(manifest, 'config.lua'), 'shared');
    assert.equal(sideOf(manifest, 'commented.lua'), 'unknown');
  });

  it('falls back to path conventions', () => {
    const empty = parseManifest('');
    assert.equal(sideOf(empty, 'sv_main.lua'), 'server');
    assert.equal(sideOf(empty, 'cl_main.lua'), 'client');
    assert.equal(sideOf(empty, 'html/app.js'), 'unknown');
  });
});
