import { afterEach, mock, test } from 'node:test';
import assert from 'node:assert/strict';
let dnsAnswers = [];
mock.module('node:dns/promises', {
  namedExports: { lookup: async () => dnsAnswers },
});
const { safeFetch, validateHost } = await import('../src/lib/ssrf-guard.ts');

// Literal IPv6 inputs never enter the DNS branch. Do not import route handlers,
// load environment files, start the app, or make real network requests here.
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

const blocked = [
  '0:0:0:0:0:0:0:0',
  '0:0:0:0:0:0:0:1',
  '0000:0000:0000:0000:0000:ffff:7f00:1',
  '0064:ff9b:0000:0000:0000:0000:7f00:0001',
  '0064:ff9b:0001:0000:0000:0000:0000:0001',
  '0100:0000:0000:0000:0000:0000:0000:0001',
  '2001:0DB8:0000:0000:0000:0000:0000:0001',
  'fc00:0:0:0:0:0:0:1',
  'fd00:0:0:0:0:0:0:1',
  'fe80:0:0:0:0:0:0:1',
  'fec0:0:0:0:0:0:0:1',
  'ff02:0:0:0:0:0:0:1',
];

for (const host of blocked) {
  test(`rejects reserved IPv6 spelling ${host}`, async () => {
    assert.equal((await validateHost(host)).ok, false);
    assert.equal((await validateHost(`[${host}]`)).ok, false);
  });
}

test('continues to accept a public IPv6 literal in expanded and compressed form', async () => {
  for (const host of ['2606:4700:4700:0:0:0:0:1111', '2606:4700:4700::1111']) {
    assert.equal((await validateHost(host)).ok, true);
  }
});

test('rejects a hostname when any mocked DNS answer is expanded reserved IPv6', async () => {
  for (const address of blocked) {
    dnsAnswers = [
      { address: '2606:4700:4700::1111', family: 6 },
      { address, family: 6 },
    ];
    assert.equal((await validateHost('camera.example')).ok, false);
  }
});

test('safeFetch blocks a reserved DNS answer without invoking fetch', async () => {
  dnsAnswers = [{ address: '0:0:0:0:0:0:0:1', family: 6 }];
  globalThis.fetch = async () => { assert.fail('network request must not be attempted'); };
  await assert.rejects(safeFetch('https://camera.example/'), /blocked target/);
});

test('safeFetch rejects a reserved literal without invoking fetch', async () => {
  globalThis.fetch = async () => { assert.fail('network request must not be attempted'); };
  await assert.rejects(safeFetch('http://[0:0:0:0:0:0:0:1]/'), /blocked target/);
});

test('safeFetch rejects a redirect to a reserved literal before a second fetch', async () => {
  let calls = 0;
  globalThis.fetch = async () => {
    calls++;
    return new Response(null, {
      status: 302,
      headers: { location: 'http://[0:0:0:0:0:0:0:1]/' },
    });
  };
  await assert.rejects(safeFetch('https://[2606:4700:4700::1111]/'), /blocked target/);
  assert.equal(calls, 1);
});
