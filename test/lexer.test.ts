import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { lexJs, lexLua } from '../src/lexer.ts';

describe('lexLua', () => {
  it('blanks comments and string contents while preserving offsets', () => {
    const src = 'local a = "load(x)" -- load(y)\nlocal b = 1';
    const { code } = lexLua(src);
    assert.equal(code.length, src.length);
    assert.equal(code.includes('load'), false);
    assert.equal(code.indexOf('local b'), src.indexOf('local b'));
  });

  it('handles long comments and long strings with levels', () => {
    const src = '--[==[ load() ]] still comment ]==]\nlocal s = [=[ a ]] b ]=] x()';
    const { code, strings } = lexLua(src);
    assert.equal(code.includes('load'), false);
    assert.ok(code.includes('x()'));
    assert.equal(strings[0]?.value, ' a ]] b ');
  });

  it('decodes decimal, hex and unicode escapes', () => {
    const { strings } = lexLua('x = "\\80\\x65\\u{72}f\\n"');
    assert.equal(strings[0]?.value, 'Perf\n');
    assert.equal(strings[0]?.escapes, 3);
  });

  it('keeps escaped quotes inside strings', () => {
    const { strings, code } = lexLua('x = "a\\"b" y = 1');
    assert.equal(strings[0]?.value, 'a"b');
    assert.ok(code.endsWith('y = 1'));
  });
});

describe('lexJs', () => {
  it('blanks comments, strings and regex literals', () => {
    const src = 'const r = /eval(")/g; // eval()\n/* eval() */ const s = "eval()"; run()';
    const { code } = lexJs(src);
    assert.equal(code.includes('eval'), false);
    assert.ok(code.includes('run()'));
  });

  it('splits template literals around interpolations', () => {
    const { strings, code } = lexJs('q(`SELECT * FROM t WHERE id = ${id} AND x = ${y}`)');
    assert.equal(strings.filter((s) => s.template).length, 3);
    assert.ok(code.includes('${id}'));
  });

  it('does not treat division as a regex', () => {
    const { code } = lexJs('const a = b / c; const d = "x" / 2; eval(z)');
    assert.ok(code.includes('eval(z)'));
  });
});
