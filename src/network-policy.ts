import { BlockList, isIP } from "node:net";
import { domainToASCII } from "node:url";

export const SPECIAL_USE_DOMAINS_REVIEWED_ON = "2026-08-17";
export const MAX_DNS_ADDRESS_ANSWERS = 128;

export const TARGET_POLICY_ERROR_CODES = {
  invalidHostname: "INPUT_DOMAIN_INVALID",
  invalidHostnameLimit: "INPUT_LIMIT_EXCEEDED",
  invalidAddressAnswer: "DNS_LOOKUP_FAILED",
  noAddressAnswer: "DNS_NO_ADDRESS",
  addressAnswerLimitExceeded: "DNS_LIMIT_EXCEEDED",
  nonPublicAddress: "SSRF_NON_PUBLIC_ADDRESS",
  mixedAddressAnswers: "SSRF_MIXED_ADDRESSES",
} as const;

export type TargetPolicyErrorCode =
  (typeof TARGET_POLICY_ERROR_CODES)[keyof typeof TARGET_POLICY_ERROR_CODES];

const ERROR_MESSAGES = {
  INPUT_DOMAIN_INVALID: "The input hostname is invalid.",
  INPUT_LIMIT_EXCEEDED: "The input hostname limit is invalid.",
  DNS_LOOKUP_FAILED: "The resolver returned an invalid address answer.",
  DNS_NO_ADDRESS: "The resolver returned no address answers.",
  DNS_LIMIT_EXCEEDED: "The resolver address-answer limit was exceeded.",
  SSRF_NON_PUBLIC_ADDRESS: "The resolver returned a non-public address.",
  SSRF_MIXED_ADDRESSES:
    "The resolver returned both public and non-public addresses.",
} as const satisfies Record<TargetPolicyErrorCode, string>;

export class TargetPolicyError extends Error {
  readonly code: TargetPolicyErrorCode;

  constructor(code: TargetPolicyErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = "TargetPolicyError";
    this.code = code;
  }
}

export interface ValidatedAddressAnswer {
  readonly address: string;
  readonly family: 4 | 6;
}

const SPECIAL_USE_DOMAINS = [
  "alt",
  "6tisch.arpa",
  "eap.arpa",
  "eap-noob.arpa",
  "home.arpa",
  "10.in-addr.arpa",
  "254.169.in-addr.arpa",
  "16.172.in-addr.arpa",
  "17.172.in-addr.arpa",
  "18.172.in-addr.arpa",
  "19.172.in-addr.arpa",
  "20.172.in-addr.arpa",
  "21.172.in-addr.arpa",
  "22.172.in-addr.arpa",
  "23.172.in-addr.arpa",
  "24.172.in-addr.arpa",
  "25.172.in-addr.arpa",
  "26.172.in-addr.arpa",
  "27.172.in-addr.arpa",
  "28.172.in-addr.arpa",
  "29.172.in-addr.arpa",
  "30.172.in-addr.arpa",
  "31.172.in-addr.arpa",
  "170.0.0.192.in-addr.arpa",
  "171.0.0.192.in-addr.arpa",
  "168.192.in-addr.arpa",
  "8.e.f.ip6.arpa",
  "9.e.f.ip6.arpa",
  "a.e.f.ip6.arpa",
  "b.e.f.ip6.arpa",
  "ipv4only.arpa",
  "resolver.arpa",
  "service.arpa",
  "example",
  "example.com",
  "example.net",
  "example.org",
  "invalid",
  "local",
  "localhost",
  "onion",
  "test",
] as const;

const IPV4_NON_PUBLIC_CIDRS = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["168.63.129.16", 32],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.31.196.0", 24],
  ["192.52.193.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["192.175.48.0", 24],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const;

const IPV6_ALLOWED_CIDR = ["2000::", 3] as const;
const IPV6_NON_PUBLIC_CIDRS = [
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["2620:4f:8000::", 48],
  ["3fff::", 20],
] as const;

function createBlockList(
  cidrs: ReadonlyArray<readonly [network: string, prefixLength: number]>,
  family: "ipv4" | "ipv6",
): BlockList {
  const blockList = new BlockList();

  for (const [network, prefixLength] of cidrs) {
    blockList.addSubnet(network, prefixLength, family);
  }

  return blockList;
}

const IPV4_NON_PUBLIC = createBlockList(IPV4_NON_PUBLIC_CIDRS, "ipv4");
const IPV6_ALLOWED = createBlockList([IPV6_ALLOWED_CIDR], "ipv6");
const IPV6_NON_PUBLIC = createBlockList(IPV6_NON_PUBLIC_CIDRS, "ipv6");

function reject(code: TargetPolicyErrorCode): never {
  throw new TargetPolicyError(code);
}

function isSpecialUseDomain(hostname: string): boolean {
  return SPECIAL_USE_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
  );
}

export function normalizeHostname(
  input: unknown,
  maximumCodeUnits = 2_048,
): string {
  if (
    !Number.isSafeInteger(maximumCodeUnits) ||
    maximumCodeUnits < 1 ||
    maximumCodeUnits > 2_048
  ) {
    reject(TARGET_POLICY_ERROR_CODES.invalidHostnameLimit);
  }

  if (
    typeof input !== "string" ||
    input.length === 0 ||
    input.length > maximumCodeUnits ||
    !input.isWellFormed() ||
    /[\s\p{Cc}]/u.test(input) ||
    /[\/\\:@?#\[\]%]/u.test(input)
  ) {
    reject(TARGET_POLICY_ERROR_CODES.invalidHostname);
  }

  let ascii: string;

  try {
    ascii = domainToASCII(input);
  } catch {
    reject(TARGET_POLICY_ERROR_CODES.invalidHostname);
  }

  if (ascii.length === 0) {
    reject(TARGET_POLICY_ERROR_CODES.invalidHostname);
  }

  if (ascii.endsWith(".")) {
    ascii = ascii.slice(0, -1);
  }

  ascii = ascii.toLowerCase();

  if (ascii.length === 0 || ascii.length > 253) {
    reject(TARGET_POLICY_ERROR_CODES.invalidHostname);
  }

  const labels = ascii.split(".");

  if (
    labels.length < 2 ||
    labels.length > 127 ||
    labels.some(
      (label) =>
        label.length === 0 ||
        label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  ) {
    reject(TARGET_POLICY_ERROR_CODES.invalidHostname);
  }

  const finalLabel = labels.at(-1);

  if (finalLabel === undefined || !/[a-z]/.test(finalLabel)) {
    reject(TARGET_POLICY_ERROR_CODES.invalidHostname);
  }

  let serializedHostname: string;

  try {
    serializedHostname = new URL(`https://${ascii}/`).hostname;
  } catch {
    reject(TARGET_POLICY_ERROR_CODES.invalidHostname);
  }

  if (
    serializedHostname !== ascii ||
    isIP(serializedHostname) !== 0 ||
    isSpecialUseDomain(ascii)
  ) {
    reject(TARGET_POLICY_ERROR_CODES.invalidHostname);
  }

  return ascii;
}

export function createTargetCandidates(input: unknown): readonly string[] {
  const hostname = normalizeHostname(input);
  const hostnames = [hostname];

  if (!hostname.startsWith("www.")) {
    try {
      hostnames.push(normalizeHostname(`www.${hostname}`));
    } catch (error) {
      if (!(error instanceof TargetPolicyError)) {
        throw error;
      }
    }
  }

  const candidates = [
    ...hostnames.map((candidate) => `https://${candidate}/`),
    ...hostnames.map((candidate) => `http://${candidate}/`),
  ];

  return Object.freeze(candidates);
}

function classifyAddress(address: unknown): {
  readonly family: 4 | 6;
  readonly isPublic: boolean;
} | undefined {
  if (
    typeof address !== "string" ||
    address.length === 0 ||
    address.length > 64 ||
    address.includes("%")
  ) {
    return undefined;
  }

  const family = isIP(address);

  if (family === 4) {
    return {
      family,
      isPublic: !IPV4_NON_PUBLIC.check(address, "ipv4"),
    };
  }

  if (family === 6) {
    return {
      family,
      isPublic:
        IPV6_ALLOWED.check(address, "ipv6") &&
        !IPV6_NON_PUBLIC.check(address, "ipv6"),
    };
  }

  return undefined;
}

export function isPublicIpAddress(address: unknown): boolean {
  return classifyAddress(address)?.isPublic === true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function validateAddressAnswers(
  input: unknown,
  maximumAnswers = MAX_DNS_ADDRESS_ANSWERS,
): readonly ValidatedAddressAnswer[] {
  if (
    !Number.isSafeInteger(maximumAnswers) ||
    maximumAnswers < 1 ||
    maximumAnswers > MAX_DNS_ADDRESS_ANSWERS
  ) {
    reject(TARGET_POLICY_ERROR_CODES.addressAnswerLimitExceeded);
  }

  if (!Array.isArray(input)) {
    reject(TARGET_POLICY_ERROR_CODES.invalidAddressAnswer);
  }

  if (input.length === 0) {
    reject(TARGET_POLICY_ERROR_CODES.noAddressAnswer);
  }

  if (input.length > maximumAnswers) {
    reject(TARGET_POLICY_ERROR_CODES.addressAnswerLimitExceeded);
  }

  const validated: ValidatedAddressAnswer[] = [];
  let publicAnswers = 0;
  let nonPublicAnswers = 0;

  for (const answer of input) {
    if (!isRecord(answer)) {
      reject(TARGET_POLICY_ERROR_CODES.invalidAddressAnswer);
    }

    const address = answer.address;
    const classification = classifyAddress(address);

    if (
      typeof address !== "string" ||
      classification === undefined ||
      answer.family !== classification.family
    ) {
      reject(TARGET_POLICY_ERROR_CODES.invalidAddressAnswer);
    }

    if (classification.isPublic) {
      publicAnswers += 1;
    } else {
      nonPublicAnswers += 1;
    }

    validated.push(
      Object.freeze({
        address,
        family: classification.family,
      }),
    );
  }

  if (nonPublicAnswers > 0) {
    reject(
      publicAnswers > 0
        ? TARGET_POLICY_ERROR_CODES.mixedAddressAnswers
        : TARGET_POLICY_ERROR_CODES.nonPublicAddress,
    );
  }

  return Object.freeze(validated);
}
