import assert from "node:assert/strict";
import { test } from "node:test";

import {
  MAX_DNS_ADDRESS_ANSWERS,
  TARGET_POLICY_ERROR_CODES,
  TargetPolicyError,
  createTargetCandidates,
  isPublicIpAddress,
  normalizeHostname,
  validateAddressAnswers,
  type TargetPolicyErrorCode,
} from "../src/network-policy.ts";

function expectPolicyError(
  action: () => unknown,
  code: TargetPolicyErrorCode,
): void {
  assert.throws(action, (error: unknown) => {
    assert.ok(error instanceof TargetPolicyError);
    assert.equal(error.code, code);
    assert.equal(error.name, "TargetPolicyError");

    return true;
  });
}

test("normalizes valid ASCII, IDNA, root-dot, and size boundaries", () => {
  assert.equal(normalizeHostname("Shop.Vendor.TLD."), "shop.vendor.tld");
  assert.equal(normalizeHostname("BÜCHER.DE."), "xn--bcher-kva.de");
  assert.equal(normalizeHostname("BÜCHER。DE。"), "xn--bcher-kva.de");
  assert.equal(normalizeHostname(`${"a".repeat(63)}.dev`), `${"a".repeat(63)}.dev`);

  const maximumLabels = `${"a.".repeat(126)}a`;

  assert.equal(maximumLabels.length, 253);
  assert.equal(normalizeHostname(maximumLabels), maximumLabels);
  assert.equal(normalizeHostname("notexample.com"), "notexample.com");
  assert.equal(normalizeHostname("example.community"), "example.community");
  assert.equal(normalizeHostname("public.arpa"), "public.arpa");
  assert.equal(normalizeHostname("a.co", 4), "a.co");
});

test("enforces a caller-selected hostname limit inside the policy ceiling", () => {
  expectPolicyError(
    () => normalizeHostname("vendor.tld", 9),
    TARGET_POLICY_ERROR_CODES.invalidHostname,
  );

  for (const invalidLimit of [0, 1.5, 2_049, Number.NaN]) {
    expectPolicyError(
      () => normalizeHostname("vendor.tld", invalidLimit),
      TARGET_POLICY_ERROR_CODES.invalidHostnameLimit,
    );
  }
});

test("rejects non-strings, whitespace, controls, surrogates, and URL syntax", () => {
  const invalidInputs: readonly unknown[] = [
    undefined,
    null,
    42,
    {},
    new String("vendor.tld"),
    "",
    " vendor.tld",
    "vendor.tld ",
    "ven dor.tld",
    "vendor\t.tld",
    "vendor\n.tld",
    "vendor\u00a0.tld",
    "vendor\u0000.tld",
    "vendor\u007f.tld",
    "vendor\u0085.tld",
    "vendor\ud800.tld",
    "vendor\udc00.tld",
    "https://vendor.tld",
    "vendor.tld/path",
    "vendor.tld\\path",
    "vendor.tld:443",
    "user@vendor.tld",
    "vendor.tld?query",
    "vendor.tld#fragment",
    "[2001:db8::1]",
    "vendor%2etld",
  ];

  for (const input of invalidInputs) {
    expectPolicyError(
      () => normalizeHostname(input),
      TARGET_POLICY_ERROR_CODES.invalidHostname,
    );
  }

  const secretInput = "user:secret@vendor.tld";

  assert.throws(() => normalizeHostname(secretInput), (error: unknown) => {
    assert.ok(error instanceof TargetPolicyError);
    assert.equal(error.message.includes(secretInput), false);

    return true;
  });
});

test("rejects malformed labels, oversized names, numeric hosts, and IP forms", () => {
  const invalidHostnames = [
    "localhost",
    "vendor.123",
    ".vendor.tld",
    "vendor..tld",
    "vendor.tld..",
    "-vendor.tld",
    "vendor-.tld",
    "vendor.-tld",
    "vendor.tld-",
    "ven_dor.tld",
    "*.vendor.tld",
    `${"a".repeat(64)}.dev`,
    `${"a.".repeat(127)}a`,
    "127.0.0.1",
    "127.1",
    "2130706433",
    "0x7f000001",
    "0177.0.0.1",
    "0x7f.0x0.0x0.0x1",
  ] as const;

  for (const hostname of invalidHostnames) {
    expectPolicyError(
      () => normalizeHostname(hostname),
      TARGET_POLICY_ERROR_CODES.invalidHostname,
    );
  }
});

test("rejects the reviewed IANA special-use names and every descendant", () => {
  const specialUseHostnames = [
    "host.alt",
    "device.6tisch.arpa",
    "client.eap.arpa",
    "client.eap-noob.arpa",
    "router.home.arpa",
    "host.10.in-addr.arpa",
    "host.254.169.in-addr.arpa",
    "host.170.0.0.192.in-addr.arpa",
    "host.171.0.0.192.in-addr.arpa",
    "host.168.192.in-addr.arpa",
    "host.8.e.f.ip6.arpa",
    "host.9.e.f.ip6.arpa",
    "host.a.e.f.ip6.arpa",
    "host.b.e.f.ip6.arpa",
    "host.ipv4only.arpa",
    "host.resolver.arpa",
    "host.service.arpa",
    "host.example",
    "example.com",
    "www.example.com",
    "example.net",
    "child.example.org",
    "host.invalid",
    "host.local",
    "host.localhost",
    "host.onion",
    "host.test",
    ...Array.from(
      { length: 16 },
      (_, index) => `host.${index + 16}.172.in-addr.arpa`,
    ),
  ] as const;

  for (const hostname of specialUseHostnames) {
    expectPolicyError(
      () => normalizeHostname(hostname),
      TARGET_POLICY_ERROR_CODES.invalidHostname,
    );
  }
});

test("builds unique target candidates in the fixed policy order", () => {
  const candidates = createTargetCandidates("Shop.Vendor.TLD.");

  assert.deepEqual(candidates, [
    "https://shop.vendor.tld/",
    "https://www.shop.vendor.tld/",
    "http://shop.vendor.tld/",
    "http://www.shop.vendor.tld/",
  ]);
  assert.equal(Object.isFrozen(candidates), true);

  assert.deepEqual(createTargetCandidates("WWW.Vendor.TLD"), [
    "https://www.vendor.tld/",
    "http://www.vendor.tld/",
  ]);

  const maximumHostname = `${"a.".repeat(126)}a`;

  assert.deepEqual(createTargetCandidates(maximumHostname), [
    `https://${maximumHostname}/`,
    `http://${maximumHostname}/`,
  ]);

  expectPolicyError(
    () => createTargetCandidates("vendor.local"),
    TARGET_POLICY_ERROR_CODES.invalidHostname,
  );
});

test("blocks every documented IPv4 special-purpose range", () => {
  const blocked = [
    "0.0.0.0",
    "0.255.255.255",
    "10.0.0.1",
    "100.64.0.1",
    "100.127.255.255",
    "127.0.0.1",
    "168.63.129.16",
    "169.254.1.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.0.0.9",
    "192.0.2.1",
    "192.31.196.1",
    "192.52.193.1",
    "192.88.99.1",
    "192.168.1.1",
    "192.175.48.1",
    "198.18.0.1",
    "198.19.255.255",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "239.255.255.255",
    "240.0.0.1",
    "255.255.255.255",
  ] as const;

  for (const address of blocked) {
    assert.equal(isPublicIpAddress(address), false, address);
  }
});

test("allows IPv4 addresses immediately outside the denied ranges", () => {
  const allowed = [
    "1.0.0.0",
    "9.255.255.255",
    "11.0.0.0",
    "100.63.255.255",
    "100.128.0.0",
    "126.255.255.255",
    "128.0.0.0",
    "168.63.129.15",
    "168.63.129.17",
    "169.253.255.255",
    "169.255.0.0",
    "172.15.255.255",
    "172.32.0.0",
    "192.0.1.1",
    "192.0.3.1",
    "192.31.195.1",
    "192.31.197.1",
    "192.52.192.1",
    "192.52.194.1",
    "192.88.98.1",
    "192.88.100.1",
    "192.167.255.255",
    "192.169.0.0",
    "192.175.47.1",
    "192.175.49.1",
    "198.17.255.255",
    "198.20.0.0",
    "198.51.99.1",
    "198.51.101.1",
    "203.0.112.1",
    "203.0.114.1",
    "223.255.255.255",
  ] as const;

  for (const address of allowed) {
    assert.equal(isPublicIpAddress(address), true, address);
  }
});

test("applies the allow-then-deny IPv6 policy at prefix boundaries", () => {
  const blocked = [
    "::",
    "::1",
    "::ffff:8.8.8.8",
    "64:ff9b::808:808",
    "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "2001::1",
    "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
    "2001:db8::1",
    "2002::1",
    "2620:4f:8000::1",
    "3fff::1",
    "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
    "4000::",
    "fc00::1",
    "fd00::1",
    "fe80::1",
    "ff00::1",
  ] as const;
  const allowed = [
    "2000::",
    "2001:200::",
    "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
    "2001:db9::",
    "2003::",
    "2001:4860:4860::8888",
    "2606:4700:4700::1111",
    "2620:4f:7fff:ffff:ffff:ffff:ffff:ffff",
    "2620:4f:8001::",
    "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "3fff:1000::",
  ] as const;

  for (const address of blocked) {
    assert.equal(isPublicIpAddress(address), false, address);
  }

  for (const address of allowed) {
    assert.equal(isPublicIpAddress(address), true, address);
  }

  assert.equal(isPublicIpAddress("2001:4860:4860:0:0:0:0:8888"), true);
  assert.equal(isPublicIpAddress("2001:4860:4860::192.0.2.1"), true);
  assert.equal(isPublicIpAddress("fe80::1%lo0"), false);
  assert.equal(isPublicIpAddress("not-an-address"), false);
  assert.equal(isPublicIpAddress(42), false);
});

test("validates and freezes a bounded all-public resolver answer set", () => {
  const answers = validateAddressAnswers([
    { address: "93.184.216.34", family: 4 },
    { address: "2606:4700:4700::1111", family: 6 },
  ]);

  assert.deepEqual(answers, [
    { address: "93.184.216.34", family: 4 },
    { address: "2606:4700:4700::1111", family: 6 },
  ]);
  assert.equal(Object.isFrozen(answers), true);
  assert.equal(Object.isFrozen(answers[0]), true);

  const duplicates = validateAddressAnswers([
    { address: "8.8.8.8", family: 4 },
    { address: "8.8.8.8", family: 4 },
  ]);

  assert.equal(duplicates.length, 2);
});

test("rejects missing, malformed, scoped, and family-mismatched answers", () => {
  expectPolicyError(
    () => validateAddressAnswers([]),
    TARGET_POLICY_ERROR_CODES.noAddressAnswer,
  );

  const invalidAnswerSets: readonly unknown[] = [
    null,
    {},
    [null],
    ["8.8.8.8"],
    [{}],
    [{ address: 42, family: 4 }],
    [{ address: "not-an-address", family: 4 }],
    [{ address: "0177.0.0.1", family: 4 }],
    [{ address: "8.8.8.8", family: 6 }],
    [{ address: "2001:4860:4860::8888", family: 4 }],
    [{ address: "fe80::1%lo0", family: 6 }],
    [{ address: "x".repeat(65), family: 6 }],
  ];

  for (const answerSet of invalidAnswerSets) {
    expectPolicyError(
      () => validateAddressAnswers(answerSet),
      TARGET_POLICY_ERROR_CODES.invalidAddressAnswer,
    );
  }
});

test("rejects all-nonpublic and mixed public/nonpublic answer sets", () => {
  expectPolicyError(
    () =>
      validateAddressAnswers([
        { address: "10.0.0.1", family: 4 },
        { address: "fe80::1", family: 6 },
      ]),
    TARGET_POLICY_ERROR_CODES.nonPublicAddress,
  );

  for (const answers of [
    [
      { address: "8.8.8.8", family: 4 },
      { address: "10.0.0.1", family: 4 },
    ],
    [
      { address: "10.0.0.1", family: 4 },
      { address: "8.8.8.8", family: 4 },
    ],
  ]) {
    expectPolicyError(
      () => validateAddressAnswers(answers),
      TARGET_POLICY_ERROR_CODES.mixedAddressAnswers,
    );
  }
});

test("checks the address-answer budget before iterating answer values", () => {
  expectPolicyError(
    () =>
      validateAddressAnswers(
        [
          { address: "not-an-address", family: 4 },
          { address: "8.8.8.8", family: 4 },
        ],
        1,
      ),
    TARGET_POLICY_ERROR_CODES.addressAnswerLimitExceeded,
  );

  const tooMany = Array.from(
    { length: MAX_DNS_ADDRESS_ANSWERS + 1 },
    () => ({ address: "8.8.8.8", family: 4 }),
  );

  expectPolicyError(
    () => validateAddressAnswers(tooMany),
    TARGET_POLICY_ERROR_CODES.addressAnswerLimitExceeded,
  );

  for (const invalidMaximum of [0, 1.5, MAX_DNS_ADDRESS_ANSWERS + 1]) {
    expectPolicyError(
      () => validateAddressAnswers([{ address: "8.8.8.8", family: 4 }], invalidMaximum),
      TARGET_POLICY_ERROR_CODES.addressAnswerLimitExceeded,
    );
  }
});
