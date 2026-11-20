/**
 * Bounds shared by every attachment inspector.
 *
 * Inspectors are synchronous code over hostile bytes. They cannot be
 * pre-empted, so each one checks the deadline cooperatively inside its loops
 * (`ctx.tick()`), and every structure that could grow without bound — the
 * decompressed bytes, the extracted text, the links — goes through a budget
 * here. Exceeding a hard limit throws `InspectionAbort` with a fixed reason
 * word; the orchestrator turns that into a fact, never a failed analysis.
 */

import { inflateRawSync, inflateSync, gunzipSync, constants as zlibConstants } from 'zlib';
import { LinkFact } from '../../types';
import { buildLinkFacts } from '../../utils/canonicalize';
import { AttachmentAnalysisSettings, InspectionReason, LimitHit } from './types';

/** A hard stop inside an inspector. `reason` is a fixed word, never file content. */
export class InspectionAbort extends Error {
  constructor(readonly reason: InspectionReason) {
    super(`attachment inspection stopped: ${reason}`);
    this.name = 'InspectionAbort';
  }
}

/** Longest URL kept from inside an attachment */
const MAX_URL_LENGTH = 2048;
/** URLs kept per attachment (the prompt shows fewer, domain-diverse) */
export const MAX_LINKS_PER_ATTACHMENT = 100;
/** Characters of text gathered per attachment before head+tail kicks in */
const TEXT_HEAD_KEEP = 60_000;
const TEXT_TAIL_KEEP = 20_000;

/**
 * Shared state for one email's attachment step: one deadline, one
 * decompression budget. Child contexts (archive entries, embedded emails)
 * share both and carry their own depth.
 */
export class InspectionContext {
  private ticks = 0;

  constructor(
    readonly settings: AttachmentAnalysisSettings,
    private readonly deadlineAt: number,
    private readonly decompression: { remaining: number },
    readonly depth = 0
  ) {}

  static forEmail(settings: AttachmentAnalysisSettings, now = Date.now()): InspectionContext {
    return new InspectionContext(settings, now + settings.timeBudgetMs, {
      remaining: settings.maxUncompressedBytes,
    });
  }

  /** The same budgets with a nearer deadline (one attachment's fair share) */
  withDeadline(deadlineAt: number): InspectionContext {
    return new InspectionContext(
      this.settings,
      Math.min(deadlineAt, this.deadlineAt),
      this.decompression,
      this.depth
    );
  }

  /** One level deeper (archive entry, embedded email) */
  child(): InspectionContext {
    return new InspectionContext(
      this.settings,
      this.deadlineAt,
      this.decompression,
      this.depth + 1
    );
  }

  get deadline(): number {
    return this.deadlineAt;
  }

  remainingMs(): number {
    return this.deadlineAt - Date.now();
  }

  /** Throws `timeout` once the deadline has passed. Cheap: reads the clock every 256 calls. */
  tick(): void {
    this.ticks = (this.ticks + 1) & 0xff;
    if (this.ticks === 0 && Date.now() > this.deadlineAt) {
      throw new InspectionAbort('timeout');
    }
  }

  /** Checks the deadline now */
  checkDeadline(): void {
    if (Date.now() > this.deadlineAt) {
      throw new InspectionAbort('timeout');
    }
  }

  /** Decompression bytes still available to this email */
  get decompressionRemaining(): number {
    return this.decompression.remaining;
  }

  /**
   * Decompress with a hard output bound: the smaller of `perCallLimit` and the
   * email's remaining budget. Returns `limit` instead of throwing when the
   * output would exceed it, so callers can disclose which limit stopped them.
   */
  decompress(
    data: Buffer,
    method: 'raw' | 'zlib' | 'gzip',
    perCallLimit: number,
    lenient = false
  ): { ok: true; data: Buffer } | { ok: false; limit: LimitHit } | { ok: false; error: true } {
    this.checkDeadline();
    const budget = this.decompression.remaining;
    if (budget <= 0) {
      return { ok: false, limit: 'total_uncompressed' };
    }
    const bound = Math.max(1, Math.min(perCallLimit, budget));
    try {
      // Lenient: a stream with a missing or damaged end yields what it can
      // (PDF writers are sloppy); the output bound applies either way.
      const options = lenient
        ? { maxOutputLength: bound, finishFlush: zlibConstants.Z_SYNC_FLUSH }
        : { maxOutputLength: bound };
      const out =
        method === 'raw'
          ? inflateRawSync(data, options)
          : method === 'zlib'
            ? inflateSync(data, options)
            : gunzipSync(data, options);
      this.decompression.remaining -= out.length;
      return { ok: true, data: out };
    } catch (error) {
      if (isBufferTooLarge(error)) {
        this.decompression.remaining -= bound;
        return { ok: false, limit: bound === perCallLimit ? 'entry_size' : 'total_uncompressed' };
      }
      return { ok: false, error: true };
    }
  }

  /**
   * Decompress only the start of a raw-deflate stream, for type sniffing:
   * a bounded prefix of the input with a sync flush, so a truncated stream
   * yields what it can. Not charged to the budget (bounded by `maxOut`).
   */
  sniffInflateRaw(data: Buffer, maxOut = 4096): Buffer {
    try {
      const out = inflateRawSync(data.subarray(0, 2048), {
        finishFlush: zlibConstants.Z_SYNC_FLUSH,
        maxOutputLength: 4 * 1024 * 1024,
      });
      return out.subarray(0, maxOut);
    } catch {
      return Buffer.alloc(0);
    }
  }
}

function isBufferTooLarge(error: unknown): boolean {
  return (
    error instanceof RangeError ||
    (typeof error === 'object' &&
      error !== null &&
      (error as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE')
  );
}

/**
 * Gathers extracted text adversarially: keeps the head and a rolling tail,
 * so padding at the start cannot push the end out, and counts everything.
 */
export class TextCollector {
  private head = '';
  private tail = '';
  private total = 0;

  add(text: string): void {
    if (!text) return;
    this.total += text.length;
    if (this.head.length < TEXT_HEAD_KEEP) {
      const room = TEXT_HEAD_KEEP - this.head.length;
      this.head += text.slice(0, room);
      text = text.slice(room);
      if (!text) return;
    }
    this.tail = (this.tail + text).slice(-TEXT_TAIL_KEEP);
  }

  get length(): number {
    return this.total;
  }

  /** The kept text; an elision marker sits where the middle was dropped */
  result(): { text: string; chars: number } {
    const kept = this.head.length + this.tail.length;
    if (kept >= this.total) {
      return { text: this.head + this.tail, chars: this.total };
    }
    return {
      text: `${this.head}\n[... ${this.total - kept} characters not kept ...]\n${this.tail}`,
      chars: this.total,
    };
  }
}

/** Collects URLs found inside an attachment, deduplicated and capped */
export class LinkCollector {
  private readonly urls = new Set<string>();
  private seen = 0;

  add(url: string | undefined | null): void {
    if (!url) return;
    const trimmed = url.trim();
    if (!/^https?:\/\//i.test(trimmed) || trimmed.length > MAX_URL_LENGTH) return;
    if (this.urls.has(trimmed)) return;
    this.seen += 1;
    if (this.urls.size < MAX_LINKS_PER_ATTACHMENT) {
      this.urls.add(trimmed);
    }
  }

  get total(): number {
    return this.seen;
  }

  get truncated(): boolean {
    return this.seen > this.urls.size;
  }

  facts(): LinkFact[] {
    return buildLinkFacts([...this.urls]);
  }
}

/** Lower-cased hostname of an absolute http(s) URL, or undefined */
export function hostOf(url: string): string | undefined {
  try {
    const parsed = new URL(url.trim());
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return undefined;
    return parsed.hostname.toLowerCase() || undefined;
  } catch {
    return undefined;
  }
}

/** Distinct values, first `n` kept */
export function distinct(values: Iterable<string>, n = 10): string[] {
  const out: string[] = [];
  for (const v of values) {
    if (!out.includes(v)) out.push(v);
    if (out.length >= n) break;
  }
  return out;
}

/** Decode the XML/HTML character entities that matter for text and URLs */
export function decodeEntities(text: string): string {
  if (text.indexOf('&') === -1) return text;
  return text.replace(/&(#x[0-9a-f]{1,6}|#[0-9]{1,7}|[a-z]{2,8});/gi, (whole, body: string) => {
    if (body[0] === '#') {
      const code =
        body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1));
      if (!Number.isFinite(code) || code < 0x20 || code > 0x10ffff) return ' ';
      try {
        return String.fromCodePoint(code);
      } catch {
        return ' ';
      }
    }
    switch (body.toLowerCase()) {
      case 'amp':
        return '&';
      case 'lt':
        return '<';
      case 'gt':
        return '>';
      case 'quot':
        return '"';
      case 'apos':
        return "'";
      case 'nbsp':
        return ' ';
      default:
        return whole;
    }
  });
}
