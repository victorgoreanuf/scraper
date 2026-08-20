import { createHash } from "node:crypto";

export type DomainSetDigest = `sha256:${string}`;

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function computeDomainSetDigest(
  domains: Iterable<string>,
): DomainSetDigest {
  const ordered = [...domains].sort(compareString);
  if (!Number.isSafeInteger(ordered.length)) {
    throw new TypeError("Domain-set size exceeds the safe-integer boundary");
  }

  const hash = createHash("sha256");
  hash.update("website-technologies-scraper/domain-set/v1\0", "utf8");
  const framing = Buffer.alloc(8);
  framing.writeBigUInt64BE(BigInt(ordered.length));
  hash.update(framing);

  let previous: string | undefined;
  for (const domain of ordered) {
    if (
      domain.length === 0
      || !domain.isWellFormed()
      || domain.includes("\0")
      || domain === previous
    ) {
      throw new TypeError("Domain set contains an invalid or duplicate domain");
    }
    previous = domain;
    const bytes = Buffer.from(domain, "utf8");
    framing.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(framing);
    hash.update(bytes);
  }

  return `sha256:${hash.digest("hex")}`;
}
