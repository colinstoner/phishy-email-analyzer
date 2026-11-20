/**
 * File-share facts: whether a link's destination is a file share on a known
 * hosting platform, and what its host and path reveal about whose share it
 * is. A common takeover pattern is a known supplier's real mailbox sending
 * a link to a share on some OTHER organization's tenant (usually another
 * compromised account), so "the share does not appear to belong to the
 * claimed sender" is a useful fact for the model.
 *
 * Pure string work on the canonical (unwrapped) URL: no network, no lookups.
 * Every value taken from the URL is attacker-chosen; each is shape-checked
 * and kept short, and the prompt builder still reduces the rendered flag to
 * one bounded line. "Unknown" is a first-class answer: nothing here claims a
 * share is unrelated to the sender unless the URL shows who owns it.
 */

import { FileShareFact } from '../types';

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
/** A OneDrive personal-site segment: the owner's UPN with `@` and `.` as `_` */
const OWNER_SEGMENT = /^[a-z0-9][a-z0-9_.-]{0,79}$/;
const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** Box subdomains that are the service itself, not an account */
const BOX_SERVICE_LABELS = new Set(['app', 'www', 'account', 'm', 'api', 'upload']);

function decodedPath(url: URL): string {
  try {
    return decodeURIComponent(url.pathname);
  } catch {
    return url.pathname;
  }
}

/**
 * Classify a canonical URL as a file share, or return null. Only hosts whose
 * file-sharing role is unambiguous from the host (and, where the host also
 * serves other things, the path shape) are recognized.
 */
export function classifyFileShare(canonicalUrl: string): FileShareFact | null {
  let url: URL;
  try {
    url = new URL(canonicalUrl);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  const host = url.hostname.toLowerCase();
  const path = decodedPath(url);

  // SharePoint Online. `<tenant>-my.sharepoint.com` is OneDrive for Business:
  // each user's personal site lives at /personal/<upn with @ and . as _>/,
  // and sharing links embed it (/:f:/g/personal/<owner>/..., /:b:/r/personal/...).
  // `<tenant>.sharepoint.com` holds team and communication sites (/sites/, /teams/).
  const sharePoint = /^([a-z0-9-]+?)(-my)?\.sharepoint\.com$/.exec(host);
  if (sharePoint && LABEL.test(sharePoint[1])) {
    const tenantLabel = sharePoint[1];
    if (sharePoint[2]) {
      const owner = /(?:^|\/)personal\/([^/?#]+)/i.exec(path)?.[1]?.toLowerCase();
      return {
        platform: 'SharePoint / OneDrive for Business',
        space: 'personal',
        tenantLabel,
        ...(owner && OWNER_SEGMENT.test(owner) ? { ownerSegment: owner } : {}),
      };
    }
    const team = /(?:^|\/)(?:sites|teams)\//i.test(path) || /^\/:[a-z]:\/[st]\//i.test(path);
    return {
      platform: 'SharePoint / OneDrive for Business',
      space: team ? 'team' : 'unknown',
      tenantLabel,
    };
  }

  // Consumer OneDrive (a personal Microsoft account, not an organization's tenant)
  if (host === 'onedrive.live.com' || host === '1drv.ms') {
    return { platform: 'OneDrive (personal Microsoft account)', space: 'consumer' };
  }

  // Google Drive / Docs. Workspace links can carry /a/<domain>/, which names
  // the Workspace account's domain.
  if (host === 'drive.google.com' || host === 'docs.google.com') {
    const domain = /^\/a\/([^/]+)\//.exec(path)?.[1]?.toLowerCase();
    return {
      platform: 'Google Drive / Docs',
      space: 'unknown',
      ...(domain && DOMAIN.test(domain) && domain.length <= 253 ? { ownerDomain: domain } : {}),
    };
  }

  // Dropbox shared links (/s/, /scl/fi/, /scl/fo/, /sh/) and direct downloads
  if (
    ((host === 'www.dropbox.com' || host === 'dropbox.com') &&
      /^\/(?:s|sh|scl\/fi|scl\/fo|l)\//.test(path)) ||
    host === 'dl.dropboxusercontent.com' ||
    host === 'dl.dropbox.com'
  ) {
    return { platform: 'Dropbox', space: 'unknown' };
  }

  // Box shared links: app.box.com/s/..., <account>.app.box.com/s/..., <account>.box.com/s/...
  const box = /^(?:([a-z0-9-]+)\.)?(?:app\.)?box\.com$/.exec(host);
  if (box && /^\/(?:s|v|file|folder)\//.test(path)) {
    const label = box[1];
    return {
      platform: 'Box',
      space: 'unknown',
      ...(label && LABEL.test(label) && !BOX_SERVICE_LABELS.has(label)
        ? { tenantLabel: label }
        : {}),
    };
  }

  // Account-subdomain platforms: <account>.egnyte.com, <account>.sharefile.com
  const account = /^([a-z0-9-]+)\.(egnyte|sharefile)\.com$/.exec(host);
  if (account && LABEL.test(account[1]) && account[1] !== 'www') {
    return {
      platform: account[2] === 'egnyte' ? 'Egnyte' : 'ShareFile',
      space: 'unknown',
      tenantLabel: account[1],
    };
  }

  if (host === 'wetransfer.com' || host.endsWith('.wetransfer.com') || host === 'we.tl') {
    return { platform: 'WeTransfer', space: 'unknown' };
  }
  if (host === 'mega.nz' && /^\/(?:file|folder)\//.test(path)) {
    return { platform: 'MEGA', space: 'unknown' };
  }
  if (host === 'www.icloud.com' && /^\/(?:iclouddrive|attachment)\//.test(path)) {
    return { platform: 'iCloud Drive', space: 'unknown' };
  }

  return null;
}

export type FileShareRelation = 'related' | 'unrelated' | 'unknown';

function compact(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** Registrable domain (last two labels) of a host name */
function registrable(host: string): string {
  return host.toLowerCase().split('.').filter(Boolean).slice(-2).join('.');
}

/**
 * Whether a file share appears to belong to the claimed sender's
 * organization, from the URL alone:
 *  - `related`: the owner's sign-in domain or Workspace domain is the
 *    sender's registrable domain, or the tenant/account label matches the
 *    sender domain's label;
 *  - `unrelated`: the URL names an owner (a OneDrive personal site, a
 *    Workspace domain) and neither it nor the tenant label matches;
 *  - `unknown`: anything else, including a tenant label that does not match
 *    when no owner is named (tenant names often differ from mail domains).
 * The sender domain is hostile text and is only compared, never rendered.
 */
export function fileShareRelation(
  share: FileShareFact,
  senderDomain: string | undefined
): FileShareRelation {
  if (!senderDomain || !DOMAIN.test(senderDomain.toLowerCase())) return 'unknown';
  const senderRegistrable = registrable(senderDomain);
  const senderLabel = senderRegistrable.split('.')[0];

  const tenantMatches =
    share.tenantLabel !== undefined &&
    (compact(share.tenantLabel) === compact(senderLabel) ||
      compact(share.tenantLabel) === compact(senderRegistrable));

  if (share.ownerSegment) {
    const underscored = senderRegistrable.replace(/\./g, '_');
    const ownerMatches =
      share.ownerSegment.endsWith(`_${underscored}`) ||
      share.ownerSegment.endsWith(`_${senderLabel}_onmicrosoft_com`);
    return ownerMatches || tenantMatches ? 'related' : 'unrelated';
  }
  if (share.ownerDomain) {
    return registrable(share.ownerDomain) === senderRegistrable || tenantMatches
      ? 'related'
      : 'unrelated';
  }
  return tenantMatches ? 'related' : 'unknown';
}

/**
 * The file-share facts for one link, as short single-line statements for
 * the VERIFIED links list: what the share is, then how it relates to the
 * claimed sender. Quoted values are shape-checked URL fragments.
 */
export function describeFileShare(
  share: FileShareFact,
  senderDomain: string | undefined
): string[] {
  const parts: string[] = [`File share on ${share.platform}`];
  if (share.space === 'personal') parts.push("a person's own site");
  if (share.space === 'team') parts.push('a team or organization site');
  if (share.space === 'consumer')
    parts.push("a personal consumer account, not an organization's tenant");
  if (share.tenantLabel) parts.push(`tenant "${share.tenantLabel}"`);
  if (share.ownerSegment) parts.push(`owner "${share.ownerSegment}"`);
  if (share.ownerDomain) parts.push(`Workspace domain ${share.ownerDomain}`);
  const description = `${parts.join(', ')} (from the URL)`;

  const relation = fileShareRelation(share, senderDomain);
  const relationText =
    relation === 'unrelated'
      ? "Hosted on a tenant that does not appear to belong to the claimed sender: the owner named in the URL does not match the claimed sender's domain"
      : relation === 'related'
        ? "The tenant or owner in the URL matches the claimed sender's domain (where the file is hosted, not proof the sender or file is safe)"
        : 'Whether this share belongs to the claimed sender cannot be told from the URL';
  return [description, relationText];
}
