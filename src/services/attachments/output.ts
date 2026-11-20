/**
 * What a format inspector hands back to the orchestrator.
 */

import { LinkCollector, TextCollector } from './limits';
import {
  ChildInspection,
  Finding,
  FindingKind,
  InspectionReason,
  LimitHit,
  RealType,
} from './types';

export interface InspectorOutput {
  findings: Finding[];
  links: LinkCollector;
  text: TextCollector;
  limitsHit: LimitHit[];
  /** Set when part of the file could not be inspected; the status becomes `partial` */
  partialReason?: InspectionReason;
  /** A container's refined type (zip → docx, OLE → msg, ...) */
  refinedType?: RealType;
  children?: ChildInspection[];
  childrenTotal?: number;
  /** An embedded email's subject: attacker-authored */
  claimedSubject?: string;
}

export function newOutput(): InspectorOutput {
  return { findings: [], links: new LinkCollector(), text: new TextCollector(), limitsHit: [] };
}

/** Record a finding; a zero count is not a finding and is dropped */
export function addFinding(
  out: InspectorOutput,
  kind: FindingKind,
  count = 1,
  hosts?: Iterable<string>
): void {
  if (!Number.isFinite(count) || count <= 0) return;
  const hostList = hosts ? [...new Set(hosts)].filter(Boolean).slice(0, 10) : undefined;
  out.findings.push({
    kind,
    count: Math.floor(count),
    ...(hostList && hostList.length > 0 ? { hosts: hostList } : {}),
  });
}

export function addLimit(out: InspectorOutput, limit: LimitHit): void {
  if (!out.limitsHit.includes(limit)) out.limitsHit.push(limit);
}

export function markPartial(out: InspectorOutput, reason: InspectionReason): void {
  out.partialReason ??= reason;
}
