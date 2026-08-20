import { constants as fsConstants } from "node:fs";
import { open, realpath, type FileHandle } from "node:fs/promises";

import {
  parquetMetadata,
  parquetReadObjects,
  snappyUncompress,
  type AsyncBuffer,
  type ColumnChunk,
  type Compressors,
  type FileMetaData,
  type RowGroup,
  type SchemaElement,
} from "hyparquet";
import { DEFAULT_PARSERS } from "hyparquet/src/convert.js";
import { deserializeTCompactProtocol } from "hyparquet/src/thrift.js";

import { computeDomainSetDigest, type DomainSetDigest } from "../domain-set.ts";
import { normalizeHostname, TargetPolicyError } from "../network-policy.ts";

const TARGET_COLUMN = "root_domain";
const PARQUET_MAGIC = Uint8Array.of(0x50, 0x41, 0x52, 0x31);
const strictUtf8Decoder = new TextDecoder("utf-8", {
  fatal: true,
  ignoreBOM: true,
});
const STRICT_PARSERS = {
  ...DEFAULT_PARSERS,
  stringFromBytes(bytes: Uint8Array): string {
    return strictUtf8Decoder.decode(bytes);
  },
};

export const INPUT_ERROR_CODES = [
  "INPUT_OPEN_FAILED",
  "INPUT_PARQUET_INVALID",
  "INPUT_SCHEMA_INVALID",
  "INPUT_LIMIT_EXCEEDED",
  "INPUT_DOMAIN_INVALID",
  "INPUT_DOMAIN_DUPLICATE",
] as const;

export type InputErrorCode = (typeof INPUT_ERROR_CODES)[number];

export interface ParquetInputLimits {
  readonly rows: number;
  readonly rowsPerRowGroup: number;
  readonly metadataBytes: number;
  readonly selectedChunkCompressedBytes: number;
  readonly selectedChunkUncompressedBytes: number;
}

export interface ParquetInputOptions {
  readonly limits: ParquetInputLimits;
  readonly hostnameCodeUnits: number;
}

export interface PreparedParquetDomains {
  readonly domainCount: number;
  readonly domainSetDigest: DomainSetDigest;
  readonly sourcePath: string;
  hasDomain(domain: string): boolean;
  domains(): AsyncGenerator<string>;
  close(): Promise<void>;
}

export class ParquetInputError extends Error {
  readonly code: InputErrorCode;
  readonly rowNumber: number | null;
  readonly firstRowNumber: number | null;

  constructor(
    code: InputErrorCode,
    message: string,
    rowNumber: number | null = null,
    firstRowNumber: number | null = null,
  ) {
    super(message);
    this.name = "ParquetInputError";
    this.code = code;
    this.rowNumber = rowNumber;
    this.firstRowNumber = firstRowNumber;
  }
}

interface RowGroupPlan {
  readonly rowCount: number;
  readonly firstRowNumber: number;
  readonly metadata: FileMetaData;
}

interface ValidatedParquet {
  readonly file: AsyncBuffer;
  readonly groups: readonly RowGroupPlan[];
  readonly uncompressedChunkBytes: number;
}

interface SchemaValidation {
  readonly root: SchemaElement;
  readonly target: SchemaElement;
  readonly targetLeafIndex: number;
  readonly leafCount: number;
}

type ThriftRecord = Record<`field_${number}`, unknown>;

const CONTRACT_MAXIMUMS = {
  rows: 1_000_000,
  rowsPerRowGroup: 65_536,
  metadataBytes: 16_777_216,
  selectedChunkCompressedBytes: 33_554_432,
  selectedChunkUncompressedBytes: 33_554_432,
  hostnameCodeUnits: 2_048,
} as const;

function inputError(
  code: InputErrorCode,
  message: string,
  rowNumber: number | null = null,
  firstRowNumber: number | null = null,
): ParquetInputError {
  return new ParquetInputError(code, message, rowNumber, firstRowNumber);
}

function invalidParquet(): ParquetInputError {
  return inputError(
    "INPUT_PARQUET_INVALID",
    "Parquet input is corrupt or truncated.",
  );
}

function invalidSchema(): ParquetInputError {
  return inputError(
    "INPUT_SCHEMA_INVALID",
    "Parquet input schema is unsupported.",
  );
}

function limitExceeded(limit: string): ParquetInputError {
  return inputError(
    "INPUT_LIMIT_EXCEEDED",
    `Parquet input exceeds the ${limit} limit.`,
  );
}

function preserveInputError(error: unknown): never {
  if (error instanceof ParquetInputError) {
    throw error;
  }

  throw invalidParquet();
}

function validatePositiveInteger(
  name: string,
  value: number,
  maximum: number,
): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new RangeError(`${name} must be an integer from 1 through ${maximum}.`);
  }
}

function validateOptions(options: ParquetInputOptions): void {
  validatePositiveInteger(
    "limits.rows",
    options.limits.rows,
    CONTRACT_MAXIMUMS.rows,
  );
  validatePositiveInteger(
    "limits.rowsPerRowGroup",
    options.limits.rowsPerRowGroup,
    CONTRACT_MAXIMUMS.rowsPerRowGroup,
  );
  validatePositiveInteger(
    "limits.metadataBytes",
    options.limits.metadataBytes,
    CONTRACT_MAXIMUMS.metadataBytes,
  );
  validatePositiveInteger(
    "limits.selectedChunkCompressedBytes",
    options.limits.selectedChunkCompressedBytes,
    CONTRACT_MAXIMUMS.selectedChunkCompressedBytes,
  );
  validatePositiveInteger(
    "limits.selectedChunkUncompressedBytes",
    options.limits.selectedChunkUncompressedBytes,
    CONTRACT_MAXIMUMS.selectedChunkUncompressedBytes,
  );
  validatePositiveInteger(
    "hostnameCodeUnits",
    options.hostnameCodeUnits,
    CONTRACT_MAXIMUMS.hostnameCodeUnits,
  );
}

function hasMagic(buffer: ArrayBuffer): boolean {
  if (buffer.byteLength !== PARQUET_MAGIC.byteLength) {
    return false;
  }

  const bytes = new Uint8Array(buffer);

  return PARQUET_MAGIC.every((byte, index) => bytes[index] === byte);
}

function guardedAsyncBuffer(source: AsyncBuffer): AsyncBuffer {
  if (!Number.isSafeInteger(source.byteLength) || source.byteLength < 0) {
    throw invalidParquet();
  }

  return {
    byteLength: source.byteLength,
    async slice(start, end = source.byteLength) {
      if (
        !Number.isSafeInteger(start) ||
        !Number.isSafeInteger(end) ||
        start < 0 ||
        end < start ||
        end > source.byteLength
      ) {
        throw invalidParquet();
      }

      let buffer: ArrayBuffer;

      try {
        buffer = await source.slice(start, end);
      } catch (error) {
        preserveInputError(error);
      }

      if (
        !(buffer instanceof ArrayBuffer) ||
        buffer.byteLength !== end - start
      ) {
        throw invalidParquet();
      }

      return buffer;
    },
  };
}

async function inspectFooter(
  file: AsyncBuffer,
  metadataLimit: number,
): Promise<{ readonly metadataLength: number; readonly metadataOffset: number }> {
  if (file.byteLength < 12) {
    throw invalidParquet();
  }

  let header: ArrayBuffer;
  let footer: ArrayBuffer;

  try {
    [header, footer] = await Promise.all([
      file.slice(0, 4),
      file.slice(file.byteLength - 8, file.byteLength),
    ]);
  } catch (error) {
    preserveInputError(error);
  }

  if (!hasMagic(header) || !hasMagic(footer.slice(4))) {
    throw invalidParquet();
  }

  const metadataLength = new DataView(footer).getUint32(0, true);
  const footerLength = metadataLength + 8;

  if (footerLength > metadataLimit) {
    throw limitExceeded("metadata/footer byte");
  }

  const metadataOffset = file.byteLength - footerLength;

  if (metadataLength < 1 || metadataOffset < 4) {
    throw invalidParquet();
  }

  return { metadataLength, metadataOffset };
}

function childCount(element: SchemaElement): number {
  const count = element.num_children ?? 0;

  if (!Number.isSafeInteger(count) || count < 0) {
    throw invalidSchema();
  }

  return count;
}

function isThriftRecord(value: unknown): value is ThriftRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rawSchemaElements(
  metadataFooter: ArrayBuffer,
  metadataLength: number,
  parsedSchema: readonly SchemaElement[],
): readonly ThriftRecord[] {
  let rawMetadata: ThriftRecord;

  try {
    rawMetadata = deserializeTCompactProtocol({
      view: new DataView(metadataFooter, 0, metadataLength),
      offset: 0,
    });
  } catch {
    throw invalidParquet();
  }

  const rawSchema = rawMetadata.field_2;

  if (!Array.isArray(rawSchema) || rawSchema.length !== parsedSchema.length) {
    throw invalidSchema();
  }

  return rawSchema.map((rawElement, index) => {
    const parsedElement = parsedSchema[index];

    if (!isThriftRecord(rawElement) || parsedElement === undefined) {
      throw invalidSchema();
    }

    const rawName = rawElement.field_4;
    let decodedName: string;

    try {
      if (!(rawName instanceof Uint8Array)) {
        throw new TypeError("Missing schema name");
      }

      decodedName = strictUtf8Decoder.decode(rawName);
    } catch {
      throw invalidSchema();
    }

    if (decodedName !== parsedElement.name) {
      throw invalidSchema();
    }

    return rawElement;
  });
}

function hasRawStringAnnotation(element: ThriftRecord): boolean {
  const convertedType = element.field_6;
  const logicalType = element.field_10;
  const hasConvertedUtf8 = convertedType === 0;
  let hasLogicalString = false;

  if (convertedType !== undefined && !hasConvertedUtf8) {
    return false;
  }

  if (logicalType !== undefined) {
    if (!isThriftRecord(logicalType)) {
      return false;
    }

    const fields = Object.keys(logicalType);
    hasLogicalString =
      fields.length === 1
      && fields[0] === "field_1"
      && isThriftRecord(logicalType.field_1);

    if (!hasLogicalString) {
      return false;
    }
  }

  return hasConvertedUtf8 || hasLogicalString;
}

function hasStringAnnotation(element: SchemaElement): boolean {
  const logicalType: unknown = element.logical_type;
  const convertedType: unknown = element.converted_type;

  if (
    logicalType !== undefined &&
    (typeof logicalType !== "object" ||
      logicalType === null ||
      !("type" in logicalType) ||
      logicalType.type !== "STRING")
  ) {
    return false;
  }

  if (convertedType !== undefined && convertedType !== "UTF8") {
    return false;
  }

  return logicalType !== undefined || convertedType !== undefined;
}

function validateSchema(
  metadata: FileMetaData,
  rawSchema: readonly ThriftRecord[],
): SchemaValidation {
  if (!Array.isArray(metadata.schema) || metadata.schema.length < 2) {
    throw invalidSchema();
  }

  const root = metadata.schema[0];

  if (
    root === undefined ||
    typeof root !== "object" ||
    root === null ||
    typeof root.name !== "string" ||
    root.name.length === 0 ||
    root.type !== undefined ||
    root.repetition_type !== undefined ||
    childCount(root) < 1
  ) {
    throw invalidSchema();
  }

  const frames: Array<{ path: readonly string[]; remaining: number }> = [
    { path: [], remaining: childCount(root) },
  ];
  const leafPaths: string[][] = [];
  let target: SchemaElement | undefined;
  let targetLeafIndex = -1;
  let targetOccurrences = 0;
  let targetSchemaIndex = -1;

  for (let index = 1; index < metadata.schema.length; index += 1) {
    while (frames.at(-1)?.remaining === 0) {
      frames.pop();
    }

    const parent = frames.at(-1);
    const element = metadata.schema[index];

    if (
      parent === undefined ||
      element === undefined ||
      typeof element !== "object" ||
      element === null ||
      typeof element.name !== "string" ||
      element.name.length === 0 ||
      element.repetition_type === undefined
    ) {
      throw invalidSchema();
    }

    parent.remaining -= 1;

    const path = [...parent.path, element.name];
    const children = childCount(element);

    if (children > 0) {
      if (element.type !== undefined) {
        throw invalidSchema();
      }

      frames.push({ path, remaining: children });
    } else {
      if (element.type === undefined) {
        throw invalidSchema();
      }

      leafPaths.push(path);
    }

    if (element.name === TARGET_COLUMN) {
      targetOccurrences += 1;

      if (path.length === 1 && children === 0) {
        target = element;
        targetLeafIndex = leafPaths.length - 1;
        targetSchemaIndex = index;
      }
    }
  }

  while (frames.at(-1)?.remaining === 0) {
    frames.pop();
  }

  if (
    frames.length !== 0 ||
    targetOccurrences !== 1 ||
    target === undefined ||
    targetLeafIndex < 0 ||
    targetSchemaIndex < 0 ||
    target.type !== "BYTE_ARRAY" ||
    (target.repetition_type !== "REQUIRED" &&
      target.repetition_type !== "OPTIONAL") ||
    !hasStringAnnotation(target) ||
    !hasRawStringAnnotation(rawSchema[targetSchemaIndex] ?? {})
  ) {
    throw invalidSchema();
  }

  return {
    root,
    target,
    targetLeafIndex,
    leafCount: leafPaths.length,
  };
}

function requiredBigInt(value: unknown): bigint {
  if (typeof value !== "bigint" || value < 0n) {
    throw invalidParquet();
  }

  return value;
}

function safeOffset(value: unknown): number {
  const offset = requiredBigInt(value);

  if (offset > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw invalidParquet();
  }

  return Number(offset);
}

function selectedChunk(
  group: RowGroup,
  schema: SchemaValidation,
): ColumnChunk {
  if (
    !Array.isArray(group.columns) ||
    group.columns.length !== schema.leafCount
  ) {
    throw invalidSchema();
  }

  const chunk = group.columns[schema.targetLeafIndex];
  const column = chunk?.meta_data;

  if (
    chunk === undefined ||
    chunk.file_path !== undefined ||
    column === undefined ||
    column.type !== "BYTE_ARRAY" ||
    !Array.isArray(column.path_in_schema) ||
    column.path_in_schema.length !== 1 ||
    column.path_in_schema[0] !== TARGET_COLUMN
  ) {
    throw invalidSchema();
  }

  return chunk;
}

function validateSelectedChunk(
  chunk: ColumnChunk,
  groupRows: bigint,
  metadataOffset: number,
  fileLength: number,
  limits: ParquetInputLimits,
): void {
  const column = chunk.meta_data;

  if (column === undefined) {
    throw invalidSchema();
  }

  if (column.codec !== "UNCOMPRESSED" && column.codec !== "SNAPPY") {
    throw invalidSchema();
  }

  const valueCount = requiredBigInt(column.num_values);
  const compressedSize = requiredBigInt(column.total_compressed_size);
  const uncompressedSize = requiredBigInt(column.total_uncompressed_size);

  if (
    valueCount !== groupRows ||
    compressedSize === 0n ||
    uncompressedSize === 0n
  ) {
    throw invalidParquet();
  }

  if (compressedSize > BigInt(limits.selectedChunkCompressedBytes)) {
    throw limitExceeded("selected compressed column chunk byte");
  }

  if (uncompressedSize > BigInt(limits.selectedChunkUncompressedBytes)) {
    throw limitExceeded("selected uncompressed column chunk byte");
  }

  const dataOffset = safeOffset(column.data_page_offset);
  const dictionaryOffset =
    column.dictionary_page_offset === undefined
      ? undefined
      : safeOffset(column.dictionary_page_offset);
  const chunkOffset = dictionaryOffset ?? dataOffset;
  const compressedBytes = Number(compressedSize);

  if (
    dataOffset < 4 ||
    dataOffset >= metadataOffset ||
    (dictionaryOffset !== undefined &&
      (dictionaryOffset < 4 || dictionaryOffset > dataOffset)) ||
    chunkOffset + compressedBytes > metadataOffset ||
    chunkOffset + compressedBytes > fileLength
  ) {
    throw invalidParquet();
  }
}

function validateMetadata(
  metadata: FileMetaData,
  rawSchema: readonly ThriftRecord[],
  metadataLength: number,
  metadataOffset: number,
  fileLength: number,
  limits: ParquetInputLimits,
): readonly RowGroupPlan[] {
  if (
    metadata.metadata_length !== metadataLength ||
    (metadata.version !== 1 && metadata.version !== 2) ||
    !Array.isArray(metadata.row_groups)
  ) {
    throw invalidParquet();
  }

  const rowCount = requiredBigInt(metadata.num_rows);

  if (rowCount === 0n) {
    throw invalidParquet();
  }

  if (rowCount > BigInt(limits.rows)) {
    throw limitExceeded("row count");
  }

  const schema = validateSchema(metadata, rawSchema);
  const groups: RowGroupPlan[] = [];
  const projectedSchema = [
    { ...schema.root, num_children: 1 },
    { ...schema.target },
  ];
  let rowsSeen = 0n;

  for (const group of metadata.row_groups) {
    if (group === undefined || typeof group !== "object") {
      throw invalidParquet();
    }

    const groupRows = requiredBigInt(group.num_rows);

    if (groupRows === 0n) {
      throw invalidParquet();
    }

    if (groupRows > BigInt(limits.rowsPerRowGroup)) {
      throw limitExceeded("row-group row count");
    }

    const chunk = selectedChunk(group, schema);

    validateSelectedChunk(
      chunk,
      groupRows,
      metadataOffset,
      fileLength,
      limits,
    );

    const firstRowNumber = Number(rowsSeen) + 1;
    rowsSeen += groupRows;

    if (rowsSeen > rowCount) {
      throw invalidParquet();
    }

    const projectedGroup: RowGroup = {
      columns: [chunk],
      total_byte_size: requiredBigInt(group.total_byte_size),
      num_rows: groupRows,
    };

    groups.push({
      rowCount: Number(groupRows),
      firstRowNumber,
      metadata: {
        version: metadata.version,
        schema: projectedSchema,
        num_rows: groupRows,
        row_groups: [projectedGroup],
        metadata_length: metadataLength,
      },
    });
  }

  if (rowsSeen !== rowCount || groups.length === 0) {
    throw invalidParquet();
  }

  return groups;
}

async function prepareParquet(
  source: AsyncBuffer,
  options: ParquetInputOptions,
): Promise<ValidatedParquet> {
  validateOptions(options);

  const file = guardedAsyncBuffer(source);
  const { metadataLength, metadataOffset } = await inspectFooter(
    file,
    options.limits.metadataBytes,
  );

  let metadata: FileMetaData;
  let metadataFooter: ArrayBuffer;

  try {
    metadataFooter = await file.slice(metadataOffset, file.byteLength);
    metadata = parquetMetadata(metadataFooter, { geoparquet: false });
  } catch (error) {
    preserveInputError(error);
  }

  const rawSchema = rawSchemaElements(
    metadataFooter,
    metadataLength,
    metadata.schema,
  );
  const groups = validateMetadata(
    metadata,
    rawSchema,
    metadataLength,
    metadataOffset,
    file.byteLength,
    options.limits,
  );

  return {
    file,
    groups,
    uncompressedChunkBytes: options.limits.selectedChunkUncompressedBytes,
  };
}

function boundedSnappyCompressor(maximumOutputBytes: number): Compressors {
  let remainingOutputBytes = maximumOutputBytes;

  return {
    SNAPPY(input, outputLength) {
      if (
        !Number.isSafeInteger(outputLength) ||
        outputLength < 0 ||
        outputLength > remainingOutputBytes
      ) {
        throw limitExceeded("selected uncompressed column chunk byte");
      }

      remainingOutputBytes -= outputLength;

      const output = new Uint8Array(outputLength);

      snappyUncompress(input, output);

      return output;
    },
  };
}

async function readGroup(
  parquet: ValidatedParquet,
  group: RowGroupPlan,
): Promise<readonly Record<string, unknown>[]> {
  let rows: Record<string, unknown>[];

  try {
    rows = await parquetReadObjects({
      file: parquet.file,
      metadata: group.metadata,
      columns: [TARGET_COLUMN],
      compressors: boundedSnappyCompressor(parquet.uncompressedChunkBytes),
      rowStart: 0,
      rowEnd: group.rowCount,
      geoparquet: false,
      parsers: STRICT_PARSERS,
      useBloomFilters: false,
      usePageIndex: false,
      utf8: false,
    });
  } catch (error) {
    preserveInputError(error);
  }

  if (rows.length !== group.rowCount) {
    throw invalidParquet();
  }

  return rows;
}

function normalizeRow(
  row: Record<string, unknown>,
  rowNumber: number,
  hostnameCodeUnits: number,
): string {
  const value = row[TARGET_COLUMN];

  if (typeof value !== "string") {
    throw inputError(
      "INPUT_DOMAIN_INVALID",
      `Parquet row ${rowNumber} contains an invalid domain.`,
      rowNumber,
    );
  }

  try {
    return normalizeHostname(value, hostnameCodeUnits);
  } catch (error) {
    if (error instanceof TargetPolicyError) {
      throw inputError(
        "INPUT_DOMAIN_INVALID",
        `Parquet row ${rowNumber} contains an invalid domain.`,
        rowNumber,
      );
    }

    throw error;
  }
}

async function preflightDomains(
  parquet: ValidatedParquet,
  hostnameCodeUnits: number,
): Promise<ReadonlyMap<string, number>> {
  const firstRows = new Map<string, number>();

  for (const group of parquet.groups) {
    const rows = await readGroup(parquet, group);

    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      const rowNumber = group.firstRowNumber + index;

      if (row === undefined) {
        throw invalidParquet();
      }

      const domain = normalizeRow(row, rowNumber, hostnameCodeUnits);
      const firstRowNumber = firstRows.get(domain);

      if (firstRowNumber !== undefined) {
        throw inputError(
          "INPUT_DOMAIN_DUPLICATE",
          `Parquet row ${rowNumber} duplicates the canonical domain from row ${firstRowNumber}.`,
          rowNumber,
          firstRowNumber,
        );
      }

      firstRows.set(domain, rowNumber);
    }
  }

  return firstRows;
}

export async function* readParquetDomains(
  file: AsyncBuffer,
  options: ParquetInputOptions,
): AsyncGenerator<string> {
  const parquet = await prepareParquet(file, options);
  const firstRows = await preflightDomains(
    parquet,
    options.hostnameCodeUnits,
  );

  for (const group of parquet.groups) {
    const rows = await readGroup(parquet, group);

    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      const rowNumber = group.firstRowNumber + index;

      if (row === undefined) {
        throw invalidParquet();
      }

      const domain = normalizeRow(row, rowNumber, options.hostnameCodeUnits);

      if (firstRows.get(domain) !== rowNumber) {
        throw invalidParquet();
      }

      yield domain;
    }
  }
}

function fileHandleBuffer(handle: FileHandle, byteLength: number): AsyncBuffer {
  return {
    byteLength,
    async slice(start, end = byteLength) {
      const length = end - start;
      const bytes = new Uint8Array(length);
      let bytesRead = 0;

      while (bytesRead < length) {
        const result = await handle.read(
          bytes,
          bytesRead,
          length - bytesRead,
          start + bytesRead,
        );

        if (result.bytesRead === 0) {
          break;
        }

        bytesRead += result.bytesRead;
      }

      return bytesRead === length ? bytes.buffer : bytes.slice(0, bytesRead).buffer;
    },
  };
}

export async function* readParquetDomainsFromFile(
  filePath: string,
  options: ParquetInputOptions,
): AsyncGenerator<string> {
  const input = await openParquetDomainsFromFile(filePath, options);

  try {
    yield* input.domains();
  } finally {
    await input.close();
  }
}

export async function openParquetDomainsFromFile(
  filePath: string,
  options: ParquetInputOptions,
): Promise<PreparedParquetDomains> {
  let handle: FileHandle | undefined;
  let byteLength: number;
  let sourcePath: string;

  try {
    sourcePath = await realpath(filePath);
    handle = await open(
      sourcePath,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
    );
    const stats = await handle.stat();

    if (!stats.isFile() || !Number.isSafeInteger(stats.size) || stats.size < 0) {
      throw new Error("Input is not a regular file.");
    }

    byteLength = stats.size;
  } catch {
    await handle?.close().catch(() => undefined);

    throw inputError(
      "INPUT_OPEN_FAILED",
      "Could not open the Parquet input file.",
    );
  }

  let parquet: ValidatedParquet;
  let firstRows: ReadonlyMap<string, number>;

  try {
    parquet = await prepareParquet(fileHandleBuffer(handle, byteLength), options);
    firstRows = await preflightDomains(parquet, options.hostnameCodeUnits);
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }

  let closePromise: Promise<void> | undefined;
  let iterationStarted = false;
  const close = (): Promise<void> => {
    closePromise ??= handle.close();
    return closePromise;
  };
  const domains = async function*(): AsyncGenerator<string> {
    if (closePromise !== undefined || iterationStarted) {
      throw new TypeError("The prepared Parquet input can be consumed only once.");
    }
    iterationStarted = true;

    try {
      for (const group of parquet.groups) {
        const rows = await readGroup(parquet, group);

        for (let index = 0; index < rows.length; index += 1) {
          const row = rows[index];
          const rowNumber = group.firstRowNumber + index;

          if (row === undefined) {
            throw invalidParquet();
          }

          const domain = normalizeRow(
            row,
            rowNumber,
            options.hostnameCodeUnits,
          );
          if (firstRows.get(domain) !== rowNumber) {
            throw invalidParquet();
          }
          yield domain;
        }
      }
    } finally {
      await close();
    }
  };

  return Object.freeze({
    domainCount: firstRows.size,
    domainSetDigest: computeDomainSetDigest(firstRows.keys()),
    sourcePath,
    hasDomain(domain: string): boolean {
      return firstRows.has(domain);
    },
    domains,
    close,
  });
}
