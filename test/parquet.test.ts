import assert from "node:assert/strict";
import { test } from "node:test";

import type { AsyncBuffer } from "hyparquet";

import {
  ParquetInputError,
  readParquetDomains,
  readParquetDomainsFromFile,
  type InputErrorCode,
  type ParquetInputLimits,
  type ParquetInputOptions,
} from "../src/input/parquet.ts";

const STOP = 0;
const I32 = 5;
const I64 = 6;
const BINARY = 8;
const LIST = 9;
const STRUCT = 12;

type CompactField = readonly [
  id: number,
  type: number,
  value: Uint8Array<ArrayBuffer>,
];
type Repetition = 0 | 1 | 2;
type Codec = 0 | 1 | 2;
type SchemaLayout = "normal" | "nested" | "duplicate";

interface FixtureOptions {
  readonly metadataVersion?: number;
  readonly repetition?: Repetition;
  readonly codec?: Codec;
  readonly physicalType?: number;
  readonly convertedType?: number | null;
  readonly logicalString?: boolean;
  readonly layout?: SchemaLayout;
  readonly extraColumn?: boolean;
  readonly extraMalformedStatistics?: boolean;
  readonly malformedUtf8?: boolean;
  readonly declaredPageUncompressedSize?: number;
}

interface ByteRange {
  readonly start: number;
  readonly end: number;
}

interface SliceRead extends ByteRange {}

interface ParquetFixture {
  readonly bytes: Uint8Array<ArrayBuffer>;
  readonly file: AsyncBuffer;
  readonly reads: SliceRead[];
  readonly targetRanges: readonly ByteRange[];
  readonly extraRanges: readonly ByteRange[];
  readonly metadataFooterBytes: number;
  readonly targetCompressedBytes: number;
  readonly targetUncompressedBytes: number;
}

interface ColumnDefinition {
  readonly name: string;
  readonly path: readonly string[];
  readonly kind: "target" | "extra";
  readonly repetition: Repetition;
  readonly codec: Codec;
  readonly physicalType: number;
}

interface EncodedChunk {
  readonly bytes: Uint8Array<ArrayBuffer>;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
}

interface ChunkDescriptor extends EncodedChunk {
  readonly column: ColumnDefinition;
  readonly offset: number;
  readonly valueCount: number;
}

function concatBytes(
  ...parts: readonly Uint8Array<ArrayBuffer>[]
): Uint8Array<ArrayBuffer> {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;

  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }

  return result;
}

function encodeVarint(value: number | bigint): Uint8Array<ArrayBuffer> {
  let current = BigInt(value);
  const bytes: number[] = [];

  do {
    let byte = Number(current & 0x7fn);

    current >>= 7n;

    if (current !== 0n) {
      byte |= 0x80;
    }

    bytes.push(byte);
  } while (current !== 0n);

  return Uint8Array.from(bytes);
}

function encodeZigzag(value: number | bigint): Uint8Array<ArrayBuffer> {
  const integer = BigInt(value);
  const encoded = integer >= 0n ? integer * 2n : -integer * 2n - 1n;

  return encodeVarint(encoded);
}

function encodeText(value: string): Uint8Array<ArrayBuffer> {
  const bytes = new TextEncoder().encode(value);

  return concatBytes(encodeVarint(bytes.length), bytes);
}

function encodeField(
  previousId: number,
  [id, type, value]: CompactField,
): Uint8Array<ArrayBuffer> {
  const delta = id - previousId;
  const header =
    delta > 0 && delta <= 15
      ? Uint8Array.of((delta << 4) | type)
      : concatBytes(Uint8Array.of(type), encodeZigzag(id));

  return concatBytes(header, value);
}

function encodeStruct(
  fields: readonly CompactField[],
): Uint8Array<ArrayBuffer> {
  const parts: Uint8Array<ArrayBuffer>[] = [];
  let previousId = 0;

  for (const field of fields) {
    parts.push(encodeField(previousId, field));
    previousId = field[0];
  }

  parts.push(Uint8Array.of(STOP));

  return concatBytes(...parts);
}

function encodeList(
  type: number,
  values: readonly Uint8Array<ArrayBuffer>[],
): Uint8Array<ArrayBuffer> {
  const header =
    values.length < 15
      ? Uint8Array.of((values.length << 4) | type)
      : concatBytes(Uint8Array.of(0xf0 | type), encodeVarint(values.length));

  return concatBytes(header, ...values);
}

function uint32LittleEndian(value: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(4);

  new DataView(bytes.buffer).setUint32(0, value, true);

  return bytes;
}

function snappyLiteral(input: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const lengthMinusOne = input.length - 1;
  let literalHeader: Uint8Array<ArrayBuffer>;

  if (input.length <= 60) {
    literalHeader = Uint8Array.of(lengthMinusOne << 2);
  } else {
    const lengthBytes: number[] = [];
    let current = lengthMinusOne;

    while (current > 0) {
      lengthBytes.push(current & 0xff);
      current >>>= 8;
    }

    literalHeader = Uint8Array.of(
      (59 + lengthBytes.length) << 2,
      ...lengthBytes,
    );
  }

  return concatBytes(encodeVarint(input.length), literalHeader, input);
}

function encodeDefinitionLevels(
  values: readonly (string | null)[],
): Uint8Array<ArrayBuffer> {
  const runs = values.map((value) =>
    concatBytes(encodeVarint(2), Uint8Array.of(value === null ? 0 : 1)),
  );
  const encoded = concatBytes(...runs);

  return concatBytes(uint32LittleEndian(encoded.length), encoded);
}

function encodeChunk(
  values: readonly (string | null)[],
  repetition: Repetition,
  codec: Codec,
  malformedUtf8 = false,
  declaredPageUncompressedSize?: number,
): EncodedChunk {
  const plainValues = values.flatMap((value, index) => {
    if (value === null) {
      return [];
    }

    const bytes =
      malformedUtf8 && index === 0
        ? Uint8Array.of(0xc3, 0x28)
        : new TextEncoder().encode(value);

    return [concatBytes(uint32LittleEndian(bytes.length), bytes)];
  });
  const plain = concatBytes(...plainValues);
  const pageData =
    repetition === 1
      ? concatBytes(encodeDefinitionLevels(values), plain)
      : plain;
  const compressedPageData = codec === 1 ? snappyLiteral(pageData) : pageData;
  const dataPageHeader = encodeStruct([
    [1, I32, encodeZigzag(values.length)],
    [2, I32, encodeZigzag(0)],
    [3, I32, encodeZigzag(3)],
    [4, I32, encodeZigzag(3)],
  ]);
  const pageHeader = encodeStruct([
    [1, I32, encodeZigzag(0)],
    [
      2,
      I32,
      encodeZigzag(declaredPageUncompressedSize ?? pageData.length),
    ],
    [3, I32, encodeZigzag(compressedPageData.length)],
    [5, STRUCT, dataPageHeader],
  ]);

  return {
    bytes: concatBytes(pageHeader, compressedPageData),
    compressedSize: pageHeader.length + compressedPageData.length,
    uncompressedSize: pageHeader.length + pageData.length,
  };
}

function schemaElement(
  column: ColumnDefinition,
  options: FixtureOptions,
): Uint8Array<ArrayBuffer> {
  const fields: CompactField[] = [
    [1, I32, encodeZigzag(column.physicalType)],
    [3, I32, encodeZigzag(column.repetition)],
    [4, BINARY, encodeText(column.name)],
  ];

  if (column.kind === "target" && options.convertedType !== null) {
    fields.push([6, I32, encodeZigzag(options.convertedType ?? 0)]);
  }

  if (column.kind === "target" && options.logicalString !== false) {
    const logicalString = encodeStruct([
      [1, STRUCT, encodeStruct([])],
    ]);

    fields.push([10, STRUCT, logicalString]);
  }

  return encodeStruct(fields);
}

function makeColumns(options: FixtureOptions): {
  readonly schema: readonly Uint8Array<ArrayBuffer>[];
  readonly columns: readonly ColumnDefinition[];
} {
  const target: ColumnDefinition = {
    name: "root_domain",
    path:
      options.layout === "nested"
        ? ["wrapper", "root_domain"]
        : ["root_domain"],
    kind: "target",
    repetition: options.repetition ?? 0,
    codec: options.codec ?? 0,
    physicalType: options.physicalType ?? 6,
  };

  if (options.layout === "nested") {
    const group = encodeStruct([
      [3, I32, encodeZigzag(0)],
      [4, BINARY, encodeText("wrapper")],
      [5, I32, encodeZigzag(1)],
    ]);

    return {
      schema: [group, schemaElement(target, options)],
      columns: [target],
    };
  }

  const columns: ColumnDefinition[] = [target];

  if (options.layout === "duplicate") {
    columns.push({ ...target });
  }

  if (options.extraColumn === true) {
    columns.push({
      name: "ignored_blob",
      path: ["ignored_blob"],
      kind: "extra",
      repetition: 0,
      codec: 2,
      physicalType: 6,
    });
  }

  return {
    schema: columns.map((column) => schemaElement(column, options)),
    columns,
  };
}

function columnMetadata(
  chunk: ChunkDescriptor,
  options: FixtureOptions,
): Uint8Array<ArrayBuffer> {
  const fields: CompactField[] = [
    [1, I32, encodeZigzag(chunk.column.physicalType)],
    [2, LIST, encodeList(I32, [encodeZigzag(0), encodeZigzag(3)])],
    [
      3,
      LIST,
      encodeList(BINARY, chunk.column.path.map((part) => encodeText(part))),
    ],
    [4, I32, encodeZigzag(chunk.column.codec)],
    [5, I64, encodeZigzag(chunk.valueCount)],
    [6, I64, encodeZigzag(chunk.uncompressedSize)],
    [7, I64, encodeZigzag(chunk.compressedSize)],
    [9, I64, encodeZigzag(chunk.offset)],
  ];

  if (
    chunk.column.kind === "extra" &&
    options.extraMalformedStatistics === true
  ) {
    const malformedBytes = concatBytes(
      encodeVarint(2),
      Uint8Array.of(0xc3, 0x28),
    );
    const statistics = encodeStruct([
      [5, BINARY, malformedBytes],
      [6, BINARY, malformedBytes],
    ]);

    fields.push([12, STRUCT, statistics]);
  }

  return encodeStruct(fields);
}

function columnChunkMetadata(
  chunk: ChunkDescriptor,
  options: FixtureOptions,
): Uint8Array<ArrayBuffer> {
  return encodeStruct([
    [2, I64, encodeZigzag(chunk.offset)],
    [3, STRUCT, columnMetadata(chunk, options)],
  ]);
}

function makeTrackingBuffer(
  bytes: Uint8Array<ArrayBuffer>,
  reads: SliceRead[],
): AsyncBuffer {
  return {
    byteLength: bytes.length,
    slice(start, end = bytes.length) {
      reads.push({ start, end });

      return bytes.slice(start, end).buffer;
    },
  };
}

function makeFixture(
  rowGroups: readonly (readonly (string | null)[])[],
  options: FixtureOptions = {},
): ParquetFixture {
  const { schema, columns } = makeColumns(options);
  const bodyParts: Uint8Array<ArrayBuffer>[] = [];
  const chunksByGroup: ChunkDescriptor[][] = [];
  const targetRanges: ByteRange[] = [];
  const extraRanges: ByteRange[] = [];
  let offset = 4;

  for (const rows of rowGroups) {
    const chunks: ChunkDescriptor[] = [];

    for (const column of columns) {
      const values =
        column.kind === "target"
          ? rows
          : rows.map((_value, index) => `opaque-${index}.invalid`);
      const encoded = encodeChunk(
        values,
        column.repetition,
        column.codec,
        column.kind === "target" && options.malformedUtf8 === true,
        column.kind === "target"
          ? options.declaredPageUncompressedSize
          : undefined,
      );
      const chunk = {
        ...encoded,
        column,
        offset,
        valueCount: rows.length,
      };
      const range = { start: offset, end: offset + encoded.compressedSize };

      chunks.push(chunk);
      bodyParts.push(encoded.bytes);

      if (column.kind === "target") {
        targetRanges.push(range);
      } else {
        extraRanges.push(range);
      }

      offset += encoded.bytes.length;
    }

    chunksByGroup.push(chunks);
  }

  const rootSchema = encodeStruct([
    [4, BINARY, encodeText("synthetic_schema")],
    [
      5,
      I32,
      encodeZigzag(options.layout === "nested" ? 1 : columns.length),
    ],
  ]);
  const rowGroupMetadata = chunksByGroup.map((chunks, groupIndex) => {
    const rows = rowGroups[groupIndex];

    assert.ok(rows);

    const compressedSize = chunks.reduce(
      (sum, chunk) => sum + chunk.compressedSize,
      0,
    );
    const uncompressedSize = chunks.reduce(
      (sum, chunk) => sum + chunk.uncompressedSize,
      0,
    );

    return encodeStruct([
      [
        1,
        LIST,
        encodeList(
          STRUCT,
          chunks.map((chunk) => columnChunkMetadata(chunk, options)),
        ),
      ],
      [2, I64, encodeZigzag(uncompressedSize)],
      [3, I64, encodeZigzag(rows.length)],
      [6, I64, encodeZigzag(compressedSize)],
    ]);
  });
  const rowCount = rowGroups.reduce((sum, rows) => sum + rows.length, 0);
  const metadata = encodeStruct([
    [1, I32, encodeZigzag(options.metadataVersion ?? 1)],
    [2, LIST, encodeList(STRUCT, [rootSchema, ...schema])],
    [3, I64, encodeZigzag(rowCount)],
    [4, LIST, encodeList(STRUCT, rowGroupMetadata)],
    [6, BINARY, encodeText("synthetic-test")],
  ]);
  const bytes = concatBytes(
    new TextEncoder().encode("PAR1"),
    ...bodyParts,
    metadata,
    uint32LittleEndian(metadata.length),
    new TextEncoder().encode("PAR1"),
  );
  const reads: SliceRead[] = [];
  const firstTargetChunk = chunksByGroup[0]?.find(
    (chunk) => chunk.column.kind === "target",
  );

  return {
    bytes,
    file: makeTrackingBuffer(bytes, reads),
    reads,
    targetRanges,
    extraRanges,
    metadataFooterBytes: metadata.length + 8,
    targetCompressedBytes: firstTargetChunk?.compressedSize ?? 0,
    targetUncompressedBytes: firstTargetChunk?.uncompressedSize ?? 0,
  };
}

function readerOptions(
  limits: Partial<ParquetInputLimits> = {},
  hostnameCodeUnits = 2_048,
): ParquetInputOptions {
  return {
    limits: {
      rows: 1_000_000,
      rowsPerRowGroup: 65_536,
      metadataBytes: 16_777_216,
      selectedChunkCompressedBytes: 33_554_432,
      selectedChunkUncompressedBytes: 33_554_432,
      ...limits,
    },
    hostnameCodeUnits,
  };
}

async function collectDomains(
  file: AsyncBuffer,
  options = readerOptions(),
): Promise<string[]> {
  const domains: string[] = [];

  for await (const domain of readParquetDomains(file, options)) {
    domains.push(domain);
  }

  return domains;
}

async function expectInputError(
  action: () => Promise<unknown>,
  code: InputErrorCode,
): Promise<ParquetInputError> {
  let captured: ParquetInputError | undefined;

  await assert.rejects(action, (error: unknown) => {
    assert.ok(error instanceof ParquetInputError);
    assert.equal(error.code, code);
    captured = error;

    return true;
  });

  assert.ok(captured);

  return captured;
}

function readCount(reads: readonly SliceRead[], range: ByteRange): number {
  return reads.filter(
    (read) => read.start === range.start && read.end === range.end,
  ).length;
}

test("reads canonical domains in row order with two bounded passes", async () => {
  const fixture = makeFixture([
    ["Shop.Vendor.TLD.", "BÜCHER.DE."],
    ["other.vendor.tld"],
  ]);

  assert.deepEqual(await collectDomains(fixture.file), [
    "shop.vendor.tld",
    "xn--bcher-kva.de",
    "other.vendor.tld",
  ]);

  for (const range of fixture.targetRanges) {
    assert.equal(readCount(fixture.reads, range), 2);
  }
});

test("accepts logical, legacy UTF8, and Snappy contract variants", async () => {
  const variants: readonly FixtureOptions[] = [
    { convertedType: null, logicalString: true },
    { convertedType: 0, logicalString: false },
    { convertedType: 0, logicalString: true, codec: 1 },
  ];

  for (const variant of variants) {
    const fixture = makeFixture([["vendor.public"]], variant);

    assert.deepEqual(await collectDomains(fixture.file), ["vendor.public"]);
  }

  const versionTwo = makeFixture([["vendor.public"]], {
    metadataVersion: 2,
  });

  assert.deepEqual(await collectDomains(versionTwo.file), ["vendor.public"]);
});

test("projects away extra columns and preserves second-pass backpressure", async () => {
  const fixture = makeFixture(
    [["first.vendor.tld"], ["second.vendor.tld"]],
    { extraColumn: true, extraMalformedStatistics: true },
  );
  const iterator = readParquetDomains(fixture.file, readerOptions());
  const first = await iterator.next();
  const firstRange = fixture.targetRanges[0];
  const secondRange = fixture.targetRanges[1];

  assert.ok(firstRange);
  assert.ok(secondRange);
  assert.deepEqual(first, { value: "first.vendor.tld", done: false });
  assert.equal(readCount(fixture.reads, firstRange), 2);
  assert.equal(readCount(fixture.reads, secondRange), 1);
  assert.ok(
    fixture.extraRanges.every((range) => readCount(fixture.reads, range) === 0),
  );

  assert.deepEqual(await iterator.next(), {
    value: "second.vendor.tld",
    done: false,
  });
  assert.equal(readCount(fixture.reads, secondRange), 2);
  assert.deepEqual(await iterator.next(), { value: undefined, done: true });
});

test("rejects canonical duplicates before emitting and reports only row numbers", async () => {
  const rawFirst = "Shop.Vendor.TLD";
  const rawDuplicate = "shop.vendor.tld.";
  const fixture = makeFixture([[rawFirst, rawDuplicate]]);
  const iterator = readParquetDomains(fixture.file, readerOptions());
  const error = await expectInputError(
    async () => iterator.next(),
    "INPUT_DOMAIN_DUPLICATE",
  );

  assert.equal(error.rowNumber, 2);
  assert.equal(error.firstRowNumber, 1);
  assert.match(error.message, /row 2/i);
  assert.match(error.message, /row 1/i);
  assert.equal(error.message.includes(rawFirst), false);
  assert.equal(error.message.includes(rawDuplicate), false);
});

test("rejects invalid and null domains before emitting without echoing values", async () => {
  const rawInvalid = " secret.vendor.tld ";
  const fixtures = [
    {
      fixture: makeFixture([["valid.vendor.tld", rawInvalid]]),
      forbidden: rawInvalid,
    },
    {
      fixture: makeFixture([["valid.vendor.tld", null]], { repetition: 1 }),
      forbidden: "null",
    },
    {
      fixture: makeFixture([["valid.vendor.tld", ""]]),
      forbidden: undefined,
    },
  ] as const;

  for (const { fixture, forbidden } of fixtures) {
    const iterator = readParquetDomains(fixture.file, readerOptions());
    const error = await expectInputError(
      async () => iterator.next(),
      "INPUT_DOMAIN_INVALID",
    );

    assert.equal(error.rowNumber, 2);
    assert.equal(error.firstRowNumber, null);
    if (forbidden !== undefined) {
      assert.equal(error.message.includes(forbidden), false);
    }
  }
});

test("fails closed on malformed UTF-8 in an annotated string", async () => {
  const fixture = makeFixture([["placeholder.vendor.tld"]], {
    malformedUtf8: true,
  });

  await expectInputError(
    async () => readParquetDomains(fixture.file, readerOptions()).next(),
    "INPUT_PARQUET_INVALID",
  );
});

test("rejects unsupported target schemas and codecs", async () => {
  const invalidSchemas: readonly FixtureOptions[] = [
    { repetition: 2 },
    { convertedType: null, logicalString: false },
    { convertedType: 19, logicalString: true },
    { convertedType: 99, logicalString: true },
    { physicalType: 1 },
    { layout: "nested" },
    { layout: "duplicate" },
    { codec: 2 },
  ];

  for (const invalidSchema of invalidSchemas) {
    const fixture = makeFixture([["vendor.public"]], invalidSchema);

    await expectInputError(
      async () => readParquetDomains(fixture.file, readerOptions()).next(),
      "INPUT_SCHEMA_INVALID",
    );
  }
});

test("enforces row, row-group, metadata, and selected chunk limits", async () => {
  const fixture = makeFixture([["first.vendor.tld", "second.vendor.tld"]]);
  const limits: readonly Partial<ParquetInputLimits>[] = [
    { rows: 1 },
    { rowsPerRowGroup: 1 },
    { metadataBytes: fixture.metadataFooterBytes - 1 },
    {
      selectedChunkCompressedBytes: fixture.targetCompressedBytes - 1,
    },
    {
      selectedChunkUncompressedBytes: fixture.targetUncompressedBytes - 1,
    },
  ];

  for (const limit of limits) {
    await expectInputError(
      async () => readParquetDomains(fixture.file, readerOptions(limit)).next(),
      "INPUT_LIMIT_EXCEEDED",
    );
  }
});

test("bounds every Snappy page allocation by the chunk budget", async () => {
  const fixture = makeFixture([["vendor.public"]], {
    codec: 1,
    declaredPageUncompressedSize: 1_000_000,
  });

  await expectInputError(
    async () =>
      readParquetDomains(
        fixture.file,
        readerOptions({
          selectedChunkUncompressedBytes: fixture.targetUncompressedBytes,
        }),
      ).next(),
    "INPUT_LIMIT_EXCEEDED",
  );
});

test("classifies corrupt, truncated, and zero-row files as invalid Parquet", async () => {
  const fixture = makeFixture([["vendor.public"]]);
  const badHeader = fixture.bytes.slice();
  const badFooter = fixture.bytes.slice();

  badHeader[0] = 0;
  badFooter[badFooter.length - 1] = 0;

  const inputs: readonly AsyncBuffer[] = [
    makeTrackingBuffer(badHeader, []),
    makeTrackingBuffer(badFooter, []),
    makeTrackingBuffer(fixture.bytes.slice(0, -1), []),
    makeFixture([[]]).file,
    makeFixture([["vendor.public"]], { metadataVersion: 3 }).file,
  ];

  for (const input of inputs) {
    await expectInputError(
      async () => readParquetDomains(input, readerOptions()).next(),
      "INPUT_PARQUET_INVALID",
    );
  }
});

test("uses the stable open-failure code without exposing the path", async () => {
  const missingPath = "/definitely-not-present/parquet-secret-input.parquet";
  const error = await expectInputError(
    async () =>
      readParquetDomainsFromFile(missingPath, readerOptions()).next(),
    "INPUT_OPEN_FAILED",
  );

  assert.equal(error.message.includes(missingPath), false);
});

test("rejects caller limits that would weaken the v1 ceilings", async () => {
  const fixture = makeFixture([["vendor.public"]]);

  await assert.rejects(
    async () =>
      readParquetDomains(
        fixture.file,
        readerOptions({ rows: 1_000_001 }),
      ).next(),
    RangeError,
  );
});
