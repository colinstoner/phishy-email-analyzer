/**
 * Attachment analysis: result types.
 *
 * Everything here is produced by Phishy's own static inspection of the
 * attachment bytes. Two kinds of value live side by side and must never be
 * confused downstream:
 *
 *  - computed facts (types, counts, booleans, fixed reason words, hosts
 *    parsed out of URLs): rendered under VERIFIED, each reduced to a single
 *    bounded line by the prompt builder;
 *  - attacker-authored content (entry names, an embedded email's subject,
 *    extracted text): fields whose name starts with `claimed` or is `text`,
 *    rendered only inside the `attachment-content` nonce fence under CLAIMED.
 */

import { LinkFact } from '../../types';

/** The file type Phishy identified from the bytes, independent of name and declared type */
export type RealType =
  | 'pdf'
  | 'html'
  | 'svg'
  | 'xml'
  | 'text'
  | 'rtf'
  | 'docx'
  | 'docm'
  | 'xlsx'
  | 'xlsm'
  | 'xlsb'
  | 'pptx'
  | 'pptm'
  | 'ooxml_other'
  | 'ooxml_encrypted'
  | 'ole_doc'
  | 'ole_xls'
  | 'ole_ppt'
  | 'ole_msg'
  | 'ole_other'
  | 'msi'
  | 'zip'
  | 'jar'
  | 'gzip'
  | 'tar'
  | 'rar'
  | '7z'
  | 'cab'
  | 'bzip2'
  | 'xz'
  | 'eml'
  | 'png'
  | 'jpeg'
  | 'gif'
  | 'bmp'
  | 'webp'
  | 'tiff'
  | 'ico'
  | 'pe_executable'
  | 'elf_executable'
  | 'macho_executable'
  | 'shortcut_lnk'
  | 'disk_image_iso'
  | 'disk_image_vhd'
  | 'chm'
  | 'onenote'
  | 'empty'
  | 'unknown';

/** Broad class of a real type: drives which inspector runs and how risky the type is */
export type TypeFamily =
  'document' | 'web' | 'archive' | 'email' | 'image' | 'executable' | 'text' | 'unknown';

/**
 * Why inspection stopped or did not happen. Fixed words: they are rendered
 * as-is in the prompt and in logs, never with any detail from the file.
 */
export type InspectionReason =
  | 'disabled'
  | 'too_large'
  | 'timeout'
  | 'malformed'
  | 'encrypted'
  | 'unsupported'
  | 'depth_limit'
  | 'budget_exhausted'
  | 'high_risk_type'
  | 'error';

/** Limits that cut an inspection short; each is disclosed to the model */
export type LimitHit =
  | 'entry_count'
  | 'entry_size'
  | 'total_uncompressed'
  | 'nesting_depth'
  | 'scan_size'
  | 'text_size'
  | 'link_count'
  | 'stream_count';

/** Something about the file name, computed by Phishy (the name itself is CLAIMED) */
export type NameFlag =
  | 'double_extension'
  | 'bidi_override'
  | 'invisible_characters'
  | 'whitespace_padding'
  | 'dangerous_extension'
  | 'extension_mismatch'
  | 'declared_type_mismatch'
  | 'no_extension';

/**
 * One computed finding. `kind` is a fixed identifier rendered with fixed
 * English text; `count` and `hosts` are the only variable parts. Hosts come
 * from parsing URLs (lower-cased hostnames), never free text.
 */
export interface Finding {
  kind: FindingKind;
  count?: number;
  hosts?: string[];
}

export type FindingKind =
  // HTML / SVG
  | 'html_forms'
  | 'html_form_posts_to_host'
  | 'html_form_posts_nowhere_visible'
  | 'html_password_fields'
  | 'html_script_tags'
  | 'html_remote_scripts'
  | 'html_inline_event_handlers'
  | 'html_iframes'
  | 'html_meta_refresh'
  | 'html_script_redirect'
  | 'html_network_requests'
  | 'html_obfuscation_decoders'
  | 'html_large_base64'
  | 'html_data_uris'
  | 'html_smuggling_markers'
  | 'html_remote_resources'
  | 'html_base_href'
  // PDF
  | 'pdf_pages'
  | 'pdf_javascript'
  | 'pdf_launch_action'
  | 'pdf_open_action'
  | 'pdf_additional_actions'
  | 'pdf_embedded_files'
  | 'pdf_submit_form'
  | 'pdf_remote_goto'
  | 'pdf_acroform'
  | 'pdf_xfa'
  | 'pdf_rich_media'
  | 'pdf_encrypted'
  | 'pdf_uri_actions'
  | 'pdf_link_annotations'
  | 'pdf_images'
  | 'pdf_text_chars'
  | 'pdf_text_undecodable'
  | 'pdf_little_text_with_links_or_images'
  | 'pdf_streams_undecodable'
  | 'pdf_object_streams'
  // Office Open XML
  | 'ooxml_macros'
  | 'ooxml_external_template'
  | 'ooxml_external_object'
  | 'ooxml_external_image'
  | 'ooxml_external_other'
  | 'ooxml_unc_paths'
  | 'ooxml_embedded_objects'
  | 'ooxml_activex'
  | 'ooxml_dde_fields'
  | 'ooxml_remote_field_codes'
  | 'ooxml_hyperlinks'
  | 'ooxml_text_chars'
  // Legacy OLE / RTF
  | 'ole_macros'
  | 'ole_embedded_objects'
  | 'ole_equation_editor'
  | 'ole_legacy_not_inspected'
  | 'rtf_embedded_objects'
  | 'rtf_equation_editor'
  // Archives
  | 'archive_entries'
  | 'archive_encrypted_entries'
  | 'archive_nested_archives'
  | 'archive_high_risk_entries'
  | 'archive_uncompressed_bytes'
  | 'archive_overlapping_entries'
  | 'archive_size_mismatch'
  // Email
  | 'email_attachments'
  | 'email_links'
  // Text
  | 'text_chars';

/** One entry of an archive, or one attachment of an embedded email */
export interface ChildInspection {
  /** Entry name as stored in the archive / attachment name: attacker-chosen, CLAIMED */
  claimedName: string;
  /** Uncompressed size in bytes as read (or as declared when not read) */
  size: number;
  /** The inspection of the entry's bytes, when they were read */
  inspection: AttachmentInspection;
}

/** Phishy's static inspection of one attachment (or archive entry) */
export interface AttachmentInspection {
  /**
   * `inspected`: every inspector for the type ran to completion.
   * `partial`: some of it ran; a limit or an unreadable part stopped the rest.
   * `not_inspected`: deliberately not parsed (high-risk type, unsupported
   * format, too large, depth limit, budget gone).
   * `failed`: the parser stopped on a malformed or hostile structure, or ran
   * out of time.
   */
  status: 'inspected' | 'partial' | 'not_inspected' | 'failed';
  /** Fixed word saying why, for anything but `inspected` */
  reason?: InspectionReason;
  realType: RealType;
  family: TypeFamily;
  /** Executables, scripts, shortcuts, disk images, installers, HTML applications */
  highRisk: boolean;
  nameFlags: NameFlag[];
  /** The final extension of the name, when it is a short alphanumeric token */
  extension?: string;
  findings: Finding[];
  /** URLs found inside, canonicalized; capped */
  links: LinkFact[];
  /** Links found before the cap */
  linksTotal: number;
  /**
   * Extracted text: ATTACKER-AUTHORED. Already bounded (head and tail kept);
   * the prompt builder bounds it again against its own budget.
   */
  text?: string;
  /** Characters of text found before any bound */
  textChars: number;
  /** Characters cut from `text` by the email's text budget (head and tail kept) */
  textShownElided?: number;
  /** An embedded email's subject: ATTACKER-AUTHORED */
  claimedSubject?: string;
  /** Archive entries or an embedded email's attachments, capped */
  children?: ChildInspection[];
  /** Entries / attachments there were in total (children may be fewer) */
  childrenTotal?: number;
  /** Image width and height in pixels, from the header */
  dimensions?: { width: number; height: number };
  limitsHit: LimitHit[];
  /** Milliseconds this inspection took */
  durationMs: number;
}

/** Limits and budgets for the whole step; see the config schema for defaults */
export interface AttachmentAnalysisSettings {
  enabled: boolean;
  /** Wall-clock budget for analysing every attachment of one email */
  timeBudgetMs: number;
  /** Attachments larger than this are not inspected */
  maxAttachmentBytes: number;
  /** Decompression budget for one email (archives, OOXML parts, PDF streams) */
  maxUncompressedBytes: number;
  /** Archive entries listed per archive (and examined, when small enough) */
  maxArchiveEntries: number;
  /** How deep archives and embedded emails are followed */
  maxDepth: number;
  /** Characters of extracted text kept per attachment for the model */
  maxTextPerAttachment: number;
  /** Characters of extracted text for all attachments of one email together */
  maxTextTotal: number;
}

export const DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS: AttachmentAnalysisSettings = {
  enabled: false,
  timeBudgetMs: 10_000,
  maxAttachmentBytes: 25 * 1024 * 1024,
  maxUncompressedBytes: 64 * 1024 * 1024,
  maxArchiveEntries: 200,
  maxDepth: 3,
  maxTextPerAttachment: 8000,
  maxTextTotal: 24_000,
};
