# Offline IPv6 SSRF regression check

Run from the repository root with a Node runtime that supports native TypeScript
stripping and experimental test module mocks (verified with Node v26.13.0):

    node --experimental-test-module-mocks --test tools/ssrf-guard-ipv6.test.mjs

This is a separate Node test, not part of the `npm test` Vitest glob. It needs no
installed project dependencies. It imports only `ssrf-guard.ts` and Node builtins;
DNS is replaced before the module is imported, and every exercised fetch is a
local mock. It does not load Next.js, environment files, camera feeds or servers.
Node may emit experimental, module-type and mock API deprecation warnings.

The regression is in `ipv6InBlocked`: textual prefixes were checked against the
input spelling. Expanded loopback, zero-padded documentation addresses and other
reserved spellings could pass `validateHost`. Canonicalizing with the WHATWG URL
parser before the existing blocklist makes literals and DNS answers follow the
same policy. Invalid/scoped IPv6 DNS answers fail closed.

The tests cover 12 reserved spellings, bracketed literals, a public address,
mixed mocked DNS answers, no-fetch rejection and redirect revalidation. Before
the fix the initial 15-test literal suite failed seven cases; after the fix the
extended 17-test suite passes.

Scope limitation: `safeFetch` already parses input URLs, so literal URL and
redirect loopback checks passed before this fix. The added protection matters
for direct `validateHost` callers and noncanonical DNS answers. The tests do not
prove that the host OS resolver returns expanded answers, nor that a deployed
endpoint was exploitable. DNS rebinding (lookup/fetch time-of-check/time-of-use)
remains outside this change; no socket-level IP pinning is implemented.
