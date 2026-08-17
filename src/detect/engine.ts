import type { ScanConfig } from "../config.ts";
import {
  EVIDENCE_SOURCES,
  createEvidenceVersion,
  createEvidenceValueMatch,
  sanitizeEvidenceKey,
  type Evidence,
  type EvidenceSource,
  type HttpEntryResult,
  type Inference,
  type PageId,
  type ScanError,
  type Technology,
} from "../model.ts";
import type {
  CompiledFingerprintCatalog,
  CompiledTechnologyDefinition,
} from "./catalog.ts";
import type {
  DetectorCandidate,
  DetectorPool,
  WorkerMatch,
} from "./pool.ts";

export interface DetectHttpContext {
  readonly catalog: CompiledFingerprintCatalog;
  readonly pool: DetectorPool;
  readonly config: ScanConfig;
  readonly signal?: AbortSignal;
}

export interface DetectHttpResult {
  readonly technologies: readonly Technology[];
  readonly errors: readonly ScanError[];
  readonly signalAdmitted: boolean;
  readonly completed: boolean;
}

interface CandidateDraft {
  readonly source: EvidenceSource;
  readonly pageId: "p1" | null;
  readonly key: string | null;
  readonly value: string;
}

interface HttpDetectorCandidate extends DetectorCandidate {
  readonly pageId: "p1" | null;
}

interface DirectDetection {
  readonly definition: CompiledTechnologyDefinition;
  readonly evidence: readonly Evidence[];
  readonly confidence: number;
  readonly version: string | null;
  readonly pageIds: readonly PageId[];
}

interface InferredState {
  readonly confidence: number;
  readonly depth: number;
  readonly parents: readonly Inference[];
}

interface InferredDraft {
  readonly confidence: number;
  readonly depth: number;
  readonly parents: Map<string, Inference>;
}

interface ClosureResult {
  readonly inferred: ReadonlyMap<string, InferredState>;
}

interface ResolutionNode {
  readonly type: "direct" | "inferred";
  readonly confidence: number;
}

interface ExclusionComponentState {
  readonly components: (readonly string[])[];
  readonly componentByNode: Map<string, number>;
  readonly externalIndegree: number[];
  readonly activeCounts: number[];
  readonly roots: Set<number>;
  readonly resolved: Set<number>;
  readonly dirty: Set<number>;
}

interface ImplicationQueueItem {
  readonly name: string;
  readonly confidence: number;
  readonly depth: number;
}

const sourceRank = new Map<EvidenceSource, number>(
  EVIDENCE_SOURCES.map((source, index) => [source, index]),
);

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareNullableString(
  left: string | null,
  right: string | null,
): number {
  if (left === null) {
    return right === null ? 0 : -1;
  }
  return right === null ? 1 : compareString(left, right);
}

function compareEvidence(left: Evidence, right: Evidence): number {
  return (sourceRank.get(left.source) ?? Number.MAX_SAFE_INTEGER)
      - (sourceRank.get(right.source) ?? Number.MAX_SAFE_INTEGER)
    || compareNullableString(left.pageId, right.pageId)
    || compareNullableString(left.key, right.key)
    || compareString(left.ruleId, right.ruleId)
    || compareString(left.match.kind, right.match.kind)
    || compareNullableString(left.match.value, right.match.value)
    || compareNullableString(left.version, right.version);
}

function evidenceIdentity(evidence: Evidence): string {
  return JSON.stringify([
    evidence.ruleId,
    evidence.collector,
    evidence.source,
    evidence.pageId,
    evidence.key,
    evidence.match.kind,
    evidence.match.value,
    evidence.version,
  ]);
}

function compareError(left: ScanError, right: ScanError): number {
  return compareString(left.code, right.code)
    || compareNullableString(left.pageId, right.pageId)
    || compareNullableString(left.ruleId, right.ruleId)
    || compareString(left.message, right.message);
}

function resultLimitError(
  catalog: CompiledFingerprintCatalog,
  message: string,
  limit: string,
): ScanError {
  return {
    stage: "detect",
    code: "RESULT_LIMIT_EXCEEDED",
    pageId: null,
    retryable: false,
    message,
    ruleId: null,
    signal: null,
    limit,
    catalogRevision: catalog.revision,
  };
}

function detectorProtocolError(catalog: CompiledFingerprintCatalog): ScanError {
  return {
    stage: "detect",
    code: "DETECTOR_UNAVAILABLE",
    pageId: null,
    retryable: false,
    message: "Detector worker returned an invalid result",
    ruleId: null,
    signal: null,
    limit: null,
    catalogRevision: catalog.revision,
  };
}

function compareCandidateDraft(left: CandidateDraft, right: CandidateDraft): number {
  return (sourceRank.get(left.source) ?? Number.MAX_SAFE_INTEGER)
      - (sourceRank.get(right.source) ?? Number.MAX_SAFE_INTEGER)
    || compareNullableString(left.pageId, right.pageId)
    || compareNullableString(left.key, right.key)
    || compareString(left.value, right.value);
}

function candidateIdentity(candidate: CandidateDraft): string {
  return JSON.stringify([
    "http",
    candidate.source,
    candidate.pageId,
    candidate.key,
    candidate.value,
  ]);
}

function collectCandidates(
  input: HttpEntryResult,
  config: ScanConfig,
): readonly HttpDetectorCandidate[] {
  const candidates: CandidateDraft[] = [];
  const add = (
    source: EvidenceSource,
    pageId: "p1" | null,
    key: string | null,
    value: string,
  ): void => {
    candidates.push({ source, pageId, key, value });
  };
  const response = input.kind === "html" ? input.page.response : input.response;

  if (response !== null) {
    const pageId = input.kind === "html" ? "p1" : null;
    add("url", pageId, null, response.finalNetworkUrl);
    for (const redirect of response.redirects) {
      add("url", pageId, null, redirect.fromUrl);
      add("url", pageId, null, redirect.toUrl);
    }
    for (const header of response.headers) {
      add("header", pageId, header.name.toLowerCase(), header.value);
    }
    for (const cookie of response.cookies) {
      add("cookie", pageId, cookie.name, cookie.value);
    }
  }

  if (input.kind === "html") {
    add("html", "p1", null, input.page.html);
    add("text", "p1", null, input.page.text);
    for (const item of input.page.metadata) {
      add("meta", "p1", item.key.toLowerCase(), item.value);
    }
    const scriptUrls = [...new Set(
      input.page.resources
        .filter((resource) => resource.kind === "script")
        .map((resource) => resource.url),
    )].sort(compareString).slice(0, config.limits.scripts.urlCandidatesPerDomain);
    for (const url of scriptUrls) {
      add("script_url", "p1", "src", url);
    }
  }

  for (const robots of input.robots) {
    add("robots", null, null, robots.text);
  }

  const unique = new Map<string, CandidateDraft>();
  for (const candidate of candidates) {
    unique.set(candidateIdentity(candidate), candidate);
  }

  return [...unique.values()]
    .sort(compareCandidateDraft)
    .map((candidate, index) => Object.freeze({
      id: `c${String(index).padStart(8, "0")}`,
      source: candidate.source,
      pageId: candidate.pageId,
      key: candidate.key,
      value: candidate.value,
    }));
}

function evidenceFromMatch(
  match: WorkerMatch,
  candidates: readonly HttpDetectorCandidate[],
  catalog: CompiledFingerprintCatalog,
  config: ScanConfig,
): Evidence | null {
  const rule = catalog.rules[match.ruleOrdinal];
  const candidate = candidates[match.candidateOrdinal];
  if (
    rule === undefined
    || candidate === undefined
    || rule.source !== candidate.source
    || !Number.isSafeInteger(match.index)
    || !Number.isSafeInteger(match.length)
    || match.index < 0
    || match.length < 0
    || match.index + match.length > candidate.value.length
  ) {
    return null;
  }
  const evidenceKey = sanitizeEvidenceKey(
    rule.source,
    candidate.key,
    config,
  );

  if (rule.matchMode === "presence") {
    return Object.freeze({
      collector: "http",
      source: rule.source,
      pageId: candidate.pageId,
      key: evidenceKey,
      match: Object.freeze({ kind: "presence", value: null, truncated: false }),
      ruleId: rule.ruleId,
      pattern: null,
      confidence: rule.confidence,
      version: null,
    });
  }
  if (rule.pattern === null) {
    return null;
  }

  const matchedValue = candidate.value.slice(
    match.index,
    match.index + match.length,
  );
  const evidenceMatch = createEvidenceValueMatch({
    source: rule.source,
    key: candidate.key,
    observedValue: candidate.value,
    matchedValue,
    scanConfig: config,
  });
  return Object.freeze({
    collector: "http",
    source: rule.source,
    pageId: candidate.pageId,
    key: evidenceKey,
    match: Object.freeze(evidenceMatch),
    ruleId: rule.ruleId,
    pattern: rule.pattern,
    confidence: rule.confidence,
    version: evidenceMatch.kind === "value"
      ? createEvidenceVersion({
        version: match.version,
        source: rule.source,
        observedValue: candidate.value,
        matchedValue,
        matchIndex: match.index,
        matchLength: match.length,
        scanConfig: config,
      })
      : null,
  });
}

function directConfidence(evidence: readonly Evidence[]): number {
  const rules = new Map<string, number>();
  for (const item of evidence) {
    rules.set(item.ruleId, Math.max(rules.get(item.ruleId) ?? 0, item.confidence));
  }
  let confidence = 0;
  for (const value of rules.values()) {
    confidence += value;
  }
  return Math.min(100, confidence);
}

function directVersion(evidence: readonly Evidence[]): string | null {
  const scores = new Map<string, Map<string, number>>();
  for (const item of evidence) {
    if (item.version === null) {
      continue;
    }
    const rules = scores.get(item.version) ?? new Map<string, number>();
    rules.set(item.ruleId, Math.max(rules.get(item.ruleId) ?? 0, item.confidence));
    scores.set(item.version, rules);
  }
  let best = -1;
  let winner: string | null = null;
  let tied = false;
  for (const [version, rules] of [...scores].sort(([left], [right]) =>
    compareString(left, right))) {
    let score = 0;
    for (const confidence of rules.values()) {
      score += confidence;
    }
    if (score > best) {
      best = score;
      winner = version;
      tied = false;
    } else if (score === best) {
      tied = true;
    }
  }
  return tied ? null : winner;
}

function inferenceVersion(parents: readonly Inference[], confidence: number): string | null {
  const versions = new Set(
    parents
      .filter((parent) => parent.confidence === confidence && parent.version !== null)
      .map((parent) => parent.version as string),
  );
  return versions.size === 1 ? [...versions][0] ?? null : null;
}

function compareInference(left: Inference, right: Inference): number {
  return compareString(left.technology, right.technology)
    || compareString(left.ruleId, right.ruleId);
}

function inferenceIdentity(inference: Inference): string {
  return `${inference.technology}\u0000${inference.ruleId}`;
}

function compareImplicationPriority(
  left: ImplicationQueueItem,
  right: ImplicationQueueItem,
): number {
  return right.confidence - left.confidence
    || left.depth - right.depth
    || compareString(left.name, right.name);
}

function pushImplication(
  heap: ImplicationQueueItem[],
  item: ImplicationQueueItem,
): void {
  heap.push(item);
  let index = heap.length - 1;
  while (index > 0) {
    const parentIndex = Math.floor((index - 1) / 2);
    const parent = heap[parentIndex];
    if (parent === undefined || compareImplicationPriority(parent, item) <= 0) {
      break;
    }
    heap[index] = parent;
    index = parentIndex;
  }
  heap[index] = item;
}

function popImplication(
  heap: ImplicationQueueItem[],
): ImplicationQueueItem | undefined {
  const first = heap[0];
  const last = heap.pop();
  if (first === undefined || last === undefined || heap.length === 0) {
    return first;
  }

  let index = 0;
  while (true) {
    const leftIndex = index * 2 + 1;
    const rightIndex = leftIndex + 1;
    let nextIndex = leftIndex;
    const left = heap[leftIndex];
    const right = heap[rightIndex];
    if (left === undefined) {
      break;
    }
    if (right !== undefined && compareImplicationPriority(right, left) < 0) {
      nextIndex = rightIndex;
    }
    if (compareImplicationPriority(last, heap[nextIndex]!) <= 0) {
      break;
    }
    heap[index] = heap[nextIndex]!;
    index = nextIndex;
  }
  heap[index] = last;
  return first;
}

function computeImplications(
  direct: ReadonlyMap<string, DirectDetection>,
  definitions: ReadonlyMap<string, CompiledTechnologyDefinition>,
  forbidden: ReadonlySet<string> = new Set<string>(),
  allowed: ReadonlySet<string> | null = null,
): ClosureResult {
  const inferred = new Map<string, InferredDraft>();
  const queue: ImplicationQueueItem[] = [];
  for (const [name, detection] of direct) {
    if ((definitions.get(name)?.implies.length ?? 0) > 0) {
      pushImplication(queue, {
        name,
        confidence: detection.confidence,
        depth: 0,
      });
    }
  }

  while (queue.length > 0) {
    const current = popImplication(queue);
    if (current === undefined) {
      break;
    }
    const parentName = current.name;
    const directParent = direct.get(parentName);
    const inferredParent = inferred.get(parentName);
    const parentConfidence = directParent?.confidence ?? inferredParent?.confidence;
    const parentDepth = directParent === undefined ? inferredParent?.depth : 0;
    if (
      parentConfidence === undefined
      || parentDepth === undefined
      || parentConfidence !== current.confidence
      || parentDepth !== current.depth
    ) {
      continue;
    }
    const definition = definitions.get(parentName);
    if (definition === undefined) {
      continue;
    }

    for (const edge of definition.implies) {
      const target = edge.technology;
      if (
        direct.has(target)
        || forbidden.has(target)
        || (allowed !== null && !allowed.has(target))
      ) {
        continue;
      }
      const confidence = Math.min(parentConfidence, edge.confidence);
      const depth = parentDepth + 1;
      const inference: Inference = Object.freeze({
        technology: parentName,
        ruleId: edge.ruleId,
        confidence,
        version: edge.version,
      });
      const previous = inferred.get(target);
      if (
        previous === undefined
        || confidence > previous.confidence
        || (confidence === previous.confidence && depth < previous.depth)
      ) {
        inferred.set(target, {
          confidence,
          depth,
          parents: new Map([[inferenceIdentity(inference), inference]]),
        });
        if ((definitions.get(target)?.implies.length ?? 0) > 0) {
          pushImplication(queue, { name: target, confidence, depth });
        }
      } else if (confidence === previous.confidence && depth === previous.depth) {
        previous.parents.set(inferenceIdentity(inference), inference);
      }
    }
  }

  return {
    inferred: new Map(
      [...inferred].map(([name, state]) => [
        name,
        {
          confidence: state.confidence,
          depth: state.depth,
          parents: Object.freeze(
            [...state.parents.values()].sort(compareInference),
          ),
        },
      ]),
    ),
  };
}

function admitDirectDetections(
  rawDirect: ReadonlyMap<string, DirectDetection>,
  definitions: ReadonlyMap<string, CompiledTechnologyDefinition>,
): {
  readonly admitted: ReadonlyMap<string, DirectDetection>;
  readonly closure: ClosureResult;
} {
  const admitted = new Map<string, DirectDetection>();
  const waitingByTechnology = new Map<string, string[]>();
  const waitingByCategory = new Map<number, string[]>();
  const orderedDirect = [...rawDirect].sort(([left], [right]) =>
    compareString(left, right));
  for (const [name, detection] of orderedDirect) {
    if (
      detection.definition.requires.length === 0
      && detection.definition.requiresCategory.length === 0
    ) {
      admitted.set(name, detection);
      continue;
    }
    for (const required of detection.definition.requires) {
      const waiting = waitingByTechnology.get(required) ?? [];
      waiting.push(name);
      waitingByTechnology.set(required, waiting);
    }
    for (const categoryId of detection.definition.requiresCategory) {
      const waiting = waitingByCategory.get(categoryId) ?? [];
      waiting.push(name);
      waitingByCategory.set(categoryId, waiting);
    }
  }

  const available = new Set<string>();
  const queue: string[] = [];
  const expose = (name: string): void => {
    if (!available.has(name)) {
      available.add(name);
      queue.push(name);
    }
  };
  for (const name of admitted.keys()) {
    expose(name);
  }

  for (let queueIndex = 0; queueIndex < queue.length; queueIndex += 1) {
    const availableName = queue[queueIndex]!;
    const candidates = new Set(
      waitingByTechnology.get(availableName) ?? [],
    );
    waitingByTechnology.delete(availableName);
    const availableDefinition = definitions.get(availableName);
    for (const category of availableDefinition?.categories ?? []) {
      const deferred: string[] = [];
      for (const candidate of waitingByCategory.get(category.id) ?? []) {
        if (candidate === availableName && !admitted.has(candidate)) {
          deferred.push(candidate);
        } else {
          candidates.add(candidate);
        }
      }
      if (deferred.length === 0) {
        waitingByCategory.delete(category.id);
      } else {
        waitingByCategory.set(category.id, deferred);
      }
    }
    for (const candidate of candidates) {
      if (candidate === availableName || admitted.has(candidate)) {
        continue;
      }
      const detection = rawDirect.get(candidate);
      if (detection !== undefined) {
        admitted.set(candidate, detection);
        expose(candidate);
      }
    }
    for (const edge of availableDefinition?.implies ?? []) {
      expose(edge.technology);
    }
  }

  return {
    admitted,
    closure: computeImplications(admitted, definitions),
  };
}

function stronglyConnectedComponents(
  nodes: ReadonlySet<string>,
  outgoing: ReadonlyMap<string, ReadonlySet<string>>,
): readonly (readonly string[])[] {
  interface VisitFrame {
    readonly node: string;
    readonly parent: string | null;
    readonly targets: readonly string[];
    nextTarget: number;
  }

  let nextIndex = 0;
  const indices = new Map<string, number>();
  const low = new Map<string, number>();
  const stack: string[] = [];
  const onStack = new Set<string>();
  const components: string[][] = [];
  const targetsByNode = new Map(
    [...nodes].map((node) => [
      node,
      [...(outgoing.get(node) ?? [])]
        .filter((target) => nodes.has(target))
        .sort(compareString),
    ]),
  );
  const beginVisit = (
    node: string,
    parent: string | null,
    visits: VisitFrame[],
  ): void => {
    indices.set(node, nextIndex);
    low.set(node, nextIndex);
    nextIndex += 1;
    stack.push(node);
    onStack.add(node);
    visits.push({
      node,
      parent,
      targets: targetsByNode.get(node) ?? [],
      nextTarget: 0,
    });
  };

  for (const root of [...nodes].sort(compareString)) {
    if (indices.has(root)) {
      continue;
    }
    const visits: VisitFrame[] = [];
    beginVisit(root, null, visits);

    while (visits.length > 0) {
      const frame = visits[visits.length - 1]!;
      const target = frame.targets[frame.nextTarget];
      if (target !== undefined) {
        frame.nextTarget += 1;
        if (!indices.has(target)) {
          beginVisit(target, frame.node, visits);
        } else if (onStack.has(target)) {
          low.set(
            frame.node,
            Math.min(low.get(frame.node)!, indices.get(target)!),
          );
        }
        continue;
      }

      visits.pop();
      if (frame.parent !== null) {
        low.set(
          frame.parent,
          Math.min(low.get(frame.parent)!, low.get(frame.node)!),
        );
      }
      if (low.get(frame.node) !== indices.get(frame.node)) {
        continue;
      }

      const component: string[] = [];
      while (stack.length > 0) {
        const member = stack.pop()!;
        onStack.delete(member);
        component.push(member);
        if (member === frame.node) {
          break;
        }
      }
      components.push(component.sort(compareString));
    }
  }
  return components;
}

function compareExclusionRank(
  leftName: string,
  rightName: string,
  nodes: ReadonlyMap<string, ResolutionNode>,
): number {
  const left = nodes.get(leftName);
  const right = nodes.get(rightName);
  const leftType = left?.type === "direct" ? 0 : 1;
  const rightType = right?.type === "direct" ? 0 : 1;
  return leftType - rightType
    || (right?.confidence ?? 0) - (left?.confidence ?? 0)
    || compareString(leftName, rightName);
}

function buildExclusionComponents(
  remaining: ReadonlySet<string>,
  outgoing: ReadonlyMap<string, ReadonlySet<string>>,
): ExclusionComponentState {
  const components = [...stronglyConnectedComponents(remaining, outgoing)];
  const componentByNode = new Map<string, number>();
  components.forEach((component, index) => {
    for (const name of component) {
      componentByNode.set(name, index);
    }
  });
  const externalIndegree = components.map(() => 0);
  for (const source of remaining) {
    const sourceComponent = componentByNode.get(source);
    for (const target of outgoing.get(source) ?? []) {
      if (!remaining.has(target)) {
        continue;
      }
      const targetComponent = componentByNode.get(target);
      if (
        sourceComponent !== undefined
        && targetComponent !== undefined
        && sourceComponent !== targetComponent
      ) {
        externalIndegree[targetComponent] =
          (externalIndegree[targetComponent] ?? 0) + 1;
      }
    }
  }
  return {
    components,
    componentByNode,
    externalIndegree,
    activeCounts: components.map((component) => component.length),
    roots: new Set(
      [...components.keys()].filter((index) =>
        (externalIndegree[index] ?? 0) === 0),
    ),
    resolved: new Set<number>(),
    dirty: new Set<number>(),
  };
}

function recomposeDirtyExclusionComponents(
  state: ExclusionComponentState,
  remaining: ReadonlySet<string>,
  outgoing: ReadonlyMap<string, ReadonlySet<string>>,
  incoming: ReadonlyMap<string, ReadonlySet<string>>,
): void {
  const dirtyComponents = [...state.dirty];
  state.dirty.clear();
  for (const componentIndex of dirtyComponents) {
    if (state.resolved.has(componentIndex)) {
      continue;
    }
    const active = (state.components[componentIndex] ?? []).filter((name) =>
      remaining.has(name) && state.componentByNode.get(name) === componentIndex);
    state.roots.delete(componentIndex);
    state.resolved.add(componentIndex);
    state.activeCounts[componentIndex] = 0;
    for (const name of active) {
      state.componentByNode.delete(name);
    }
    if (active.length === 0) {
      continue;
    }

    const replacements = stronglyConnectedComponents(new Set(active), outgoing);
    const replacementIndexes: number[] = [];
    for (const component of replacements) {
      const replacementIndex = state.components.length;
      replacementIndexes.push(replacementIndex);
      state.components.push(component);
      state.externalIndegree.push(0);
      state.activeCounts.push(component.length);
      for (const name of component) {
        state.componentByNode.set(name, replacementIndex);
      }
    }
    for (const replacementIndex of replacementIndexes) {
      let externalIndegree = 0;
      for (const target of state.components[replacementIndex] ?? []) {
        for (const source of incoming.get(target) ?? []) {
          if (
            remaining.has(source)
            && state.componentByNode.get(source) !== replacementIndex
          ) {
            externalIndegree += 1;
          }
        }
      }
      state.externalIndegree[replacementIndex] = externalIndegree;
      if (externalIndegree === 0) {
        state.roots.add(replacementIndex);
      }
    }
  }
}

function resolveExclusions(
  nodes: ReadonlyMap<string, ResolutionNode>,
  definitions: ReadonlyMap<string, CompiledTechnologyDefinition>,
): { readonly retained: ReadonlySet<string>; readonly suppressed: ReadonlySet<string> } {
  const outgoing = new Map<string, ReadonlySet<string>>();
  for (const name of nodes.keys()) {
    outgoing.set(name, new Set(
      (definitions.get(name)?.excludes ?? []).filter((target) => nodes.has(target)),
    ));
  }
  const incoming = new Map<string, Set<string>>(
    [...nodes.keys()].map((name) => [name, new Set<string>()]),
  );
  for (const [source, targets] of outgoing) {
    for (const target of targets) {
      incoming.get(target)?.add(source);
    }
  }
  const remaining = new Set(nodes.keys());
  const retained = new Set<string>();
  const suppressed = new Set<string>();
  const indegree = new Map([...remaining].map((name) => [name, 0]));
  for (const source of remaining) {
    for (const target of outgoing.get(source) ?? []) {
      indegree.set(target, (indegree.get(target) ?? 0) + 1);
    }
  }
  const zero = new Set(
    [...remaining].filter((name) => (indegree.get(name) ?? 0) === 0),
  );
  let componentState: ExclusionComponentState | null = null;
  const remove = (name: string, outcome: "retained" | "suppressed"): void => {
    if (!remaining.has(name)) {
      return;
    }
    const state = componentState;
    const sourceComponent = state?.componentByNode.get(name);
    if (
      state !== null
      && sourceComponent !== undefined
    ) {
      const nextActiveCount = Math.max(
        0,
        (state.activeCounts[sourceComponent] ?? 0) - 1,
      );
      state.activeCounts[sourceComponent] = nextActiveCount;
      state.componentByNode.delete(name);
      if (!state.resolved.has(sourceComponent)) {
        state.roots.delete(sourceComponent);
        if (nextActiveCount === 0) {
          state.resolved.add(sourceComponent);
          state.dirty.delete(sourceComponent);
        } else {
          state.dirty.add(sourceComponent);
        }
      }
    }
    remaining.delete(name);
    zero.delete(name);
    (outcome === "retained" ? retained : suppressed).add(name);
    for (const target of outgoing.get(name) ?? []) {
      if (!remaining.has(target)) {
        continue;
      }
      const nextIndegree = (indegree.get(target) ?? 0) - 1;
      indegree.set(target, nextIndegree);
      if (nextIndegree === 0) {
        zero.add(target);
      }
      const activeState = componentState;
      const targetComponent = activeState?.componentByNode.get(target);
      const activeSourceComponent = sourceComponent;
      if (
        activeState !== null
        && activeSourceComponent !== undefined
        && targetComponent !== undefined
        && activeSourceComponent !== targetComponent
      ) {
        const nextExternal =
          (activeState.externalIndegree[targetComponent] ?? 0) - 1;
        activeState.externalIndegree[targetComponent] = nextExternal;
        if (
          nextExternal === 0
          && !activeState.resolved.has(targetComponent)
        ) {
          activeState.roots.add(targetComponent);
        }
      }
    }
  };

  while (remaining.size > 0) {
    const zeroBatch = [...zero]
      .filter((name) => remaining.has(name) && indegree.get(name) === 0)
      .sort(compareString);
    zero.clear();
    if (zeroBatch.length > 0) {
      const newlySuppressed = new Set<string>();
      for (const winner of zeroBatch) {
        for (const target of outgoing.get(winner) ?? []) {
          if (remaining.has(target)) {
            newlySuppressed.add(target);
          }
        }
      }
      for (const winner of zeroBatch) {
        remove(winner, "retained");
      }
      for (const target of newlySuppressed) {
        remove(target, "suppressed");
      }
      continue;
    }

    if (componentState === null) {
      componentState = buildExclusionComponents(remaining, outgoing);
    } else if (
      componentState.dirty.size > 0
      && ![...componentState.roots].some((index) =>
        !componentState!.resolved.has(index)
        && !componentState!.dirty.has(index))
    ) {
      recomposeDirtyExclusionComponents(
        componentState,
        remaining,
        outgoing,
        incoming,
      );
    }
    const state = componentState;
    const zeroComponents = [...state.roots]
      .filter((index) =>
        !state.resolved.has(index) && !state.dirty.has(index))
      .sort((left, right) => compareString(
        state.components[left]?.[0] ?? "",
        state.components[right]?.[0] ?? "",
      ));
    if (zeroComponents.length === 0) {
      throw new Error("Exclusion graph resolution made no progress");
    }
    for (const componentIndex of zeroComponents) {
      state.roots.delete(componentIndex);
      state.resolved.add(componentIndex);
      const ranked = (state.components[componentIndex] ?? [])
        .filter((name) => remaining.has(name))
        .sort((left, right) =>
          compareExclusionRank(left, right, nodes));
      const winner = ranked[0];
      if (winner === undefined) {
        continue;
      }
      if (ranked.length === 1) {
        remove(winner, "retained");
        continue;
      }
      for (const loser of ranked.slice(1)) {
        remove(loser, "suppressed");
      }
    }
  }
  return { retained, suppressed };
}

function materializeDirect(detection: DirectDetection): Technology {
  return Object.freeze({
    name: detection.definition.name,
    categories: detection.definition.categories,
    version: detection.version,
    confidence: detection.confidence,
    type: "direct",
    pageIds: detection.pageIds,
    evidence: detection.evidence,
    inferredFrom: Object.freeze([]),
  });
}

function materializeInferred(
  name: string,
  state: InferredState,
  definition: CompiledTechnologyDefinition,
): Technology {
  const parents = Object.freeze([...state.parents].sort(compareInference));
  return Object.freeze({
    name,
    categories: definition.categories,
    version: inferenceVersion(parents, state.confidence),
    confidence: state.confidence,
    type: "inferred",
    pageIds: Object.freeze([]),
    evidence: Object.freeze([]),
    inferredFrom: parents,
  });
}

function applyOutputLimits(
  technologies: readonly Technology[],
  config: ScanConfig,
  catalog: CompiledFingerprintCatalog,
): { readonly technologies: readonly Technology[]; readonly error: ScanError | null } {
  const evidenceCount = technologies.reduce(
    (total, technology) => total + technology.evidence.length,
    0,
  );
  const inferenceCount = technologies.reduce(
    (total, technology) => total + technology.inferredFrom.length,
    0,
  );
  const exceeded = technologies.length > config.limits.output.technologiesPerDomain
    || evidenceCount > config.limits.output.evidencePerDomain
    || inferenceCount > config.limits.output.inferencesPerDomain
    || technologies.some((technology) =>
      technology.evidence.length > config.limits.output.evidencePerTechnology
      || technology.inferredFrom.length
        > config.limits.output.inferencesPerTechnology);

  if (!exceeded) {
    return { technologies, error: null };
  }
  return {
    technologies: Object.freeze([]),
    error: resultLimitError(
      catalog,
      "Detector result exceeded a materialization output limit",
      "configured technology/evidence/inference output limits",
    ),
  };
}

export async function detectHttp(
  input: HttpEntryResult,
  context: DetectHttpContext,
): Promise<DetectHttpResult> {
  context.signal?.throwIfAborted();
  if (context.pool.catalog !== context.catalog) {
    throw new TypeError("Detector pool and catalog must share the same instance");
  }
  const candidates = collectCandidates(input, context.config);
  if (candidates.length === 0) {
    return Object.freeze({
      technologies: Object.freeze([]),
      errors: Object.freeze([]),
      signalAdmitted: false,
      completed: true,
    });
  }

  const matchResult = await context.pool.match(candidates, context.signal);
  const errors = [...matchResult.errors];
  const evidenceByTechnology = new Map<string, Map<string, Evidence>>();
  let invalidWorkerResult = false;
  for (const match of matchResult.matches) {
    const evidence = evidenceFromMatch(
      match,
      candidates,
      context.catalog,
      context.config,
    );
    const rule = context.catalog.rules[match.ruleOrdinal];
    if (evidence === null || rule === undefined) {
      invalidWorkerResult = true;
      continue;
    }
    const evidenceById = evidenceByTechnology.get(rule.technology)
      ?? new Map<string, Evidence>();
    evidenceById.set(evidenceIdentity(evidence), evidence);
    evidenceByTechnology.set(rule.technology, evidenceById);
  }
  if (invalidWorkerResult) {
    errors.push(detectorProtocolError(context.catalog));
  }

  const definitions = new Map(
    context.catalog.technologies.map((definition) => [definition.name, definition]),
  );
  const rawDirect = new Map<string, DirectDetection>();
  for (const [name, byId] of [...evidenceByTechnology].sort(([left], [right]) =>
    compareString(left, right))) {
    const definition = definitions.get(name);
    if (definition === undefined) {
      invalidWorkerResult = true;
      continue;
    }
    const evidence = [...byId.values()].sort(compareEvidence);
    if (!evidence.some((item) => item.confidence > 0)) {
      continue;
    }
    const frozenEvidence = Object.freeze(evidence);
    rawDirect.set(name, {
      definition,
      evidence: frozenEvidence,
      confidence: directConfidence(frozenEvidence),
      version: directVersion(frozenEvidence),
      pageIds: Object.freeze(
        evidence.some((item) => item.pageId === "p1") ? ["p1"] : [],
      ),
    });
  }

  const admission = admitDirectDetections(rawDirect, definitions);
  const nodes = new Map<string, ResolutionNode>();
  for (const [name, direct] of admission.admitted) {
    nodes.set(name, { type: "direct", confidence: direct.confidence });
  }
  for (const [name, inferred] of admission.closure.inferred) {
    if (!nodes.has(name)) {
      nodes.set(name, { type: "inferred", confidence: inferred.confidence });
    }
  }
  const exclusions = resolveExclusions(nodes, definitions);
  const retainedDirect = new Map(
    [...admission.admitted].filter(([name]) => exclusions.retained.has(name)),
  );
  const finalClosure = computeImplications(
    retainedDirect,
    definitions,
    exclusions.suppressed,
    exclusions.retained,
  );

  const technologies: Technology[] = [];
  for (const [name, direct] of retainedDirect) {
    if (exclusions.retained.has(name)) {
      technologies.push(materializeDirect(direct));
    }
  }
  for (const [name, inferred] of finalClosure.inferred) {
    const definition = definitions.get(name);
    if (
      definition !== undefined
      && exclusions.retained.has(name)
      && !retainedDirect.has(name)
    ) {
      technologies.push(materializeInferred(name, inferred, definition));
    }
  }
  technologies.sort((left, right) => compareString(left.name, right.name));
  const bounded = applyOutputLimits(technologies, context.config, context.catalog);
  if (bounded.error !== null) {
    errors.push(bounded.error);
  }

  const uniqueErrors = new Map<string, ScanError>();
  for (const error of errors) {
    uniqueErrors.set(JSON.stringify(error), error);
  }
  const sortedErrors = [...uniqueErrors.values()].sort(compareError);
  const errorsLimited = sortedErrors.length > context.config.limits.output.errorsPerDomain;
  let finalErrors = sortedErrors;
  if (errorsLimited) {
    const marker = sortedErrors.find((error) => error.code === "RESULT_LIMIT_EXCEEDED")
      ?? resultLimitError(
        context.catalog,
        "Detector errors exceeded the output limit",
        `${context.config.limits.output.errorsPerDomain} errors`,
      );
    const others = sortedErrors.filter((error) => error !== marker).slice(
      0,
      Math.max(0, context.config.limits.output.errorsPerDomain - 1),
    );
    finalErrors = [marker, ...others].sort(compareError);
  }

  return Object.freeze({
    technologies: Object.freeze([...bounded.technologies]),
    errors: Object.freeze(finalErrors),
    signalAdmitted: true,
    completed: matchResult.completed
      && !invalidWorkerResult
      && bounded.error === null
      && !errorsLimited,
  });
}
