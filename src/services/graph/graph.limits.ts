/**
 * Bounds and shapes shared by the Graph features and by the Graph broker's
 * wire format.
 *
 * Each of these limits what a feature will read, keep or show. They live in
 * one place because they are applied twice in broker mode: once by the
 * broker (the function that talks to Microsoft) and again by the main
 * function when it validates the broker's answer, which it treats as hostile
 * data. A bound that drifted between the two would be a bound in name only.
 *
 * No imports: this file is loaded by both sides and must stay free of
 * anything that can construct a Graph client.
 */

/** Most Internet headers read from one stored message */
export const MAX_MESSAGE_HEADERS = 500;

/** Longest subject a mailbox stores; a longer claim cannot match exactly */
export const MAX_SUBJECT_LENGTH = 255;

/** Longest address looked up (RFC 5321 path limit) */
export const MAX_ADDRESS_LENGTH = 254;

/** Longest claimed sent time read from a forwarded block */
export const MAX_CLAIMED_TIME_LENGTH = 120;

/** Recipients listed in one blast-radius report; the totals are the full counts */
export const MAX_LISTED_RECIPIENTS = 100;

/** Most burst sending IPs carried for the security team's copy of the report */
export const MAX_REPORTED_BURST_IPS = 20;

/** IPv4 or IPv6 text and nothing else: the value comes from mail flow */
export const IP_SHAPE = /^(?=.*[.:])[0-9A-Fa-f:.]{2,45}$/;

/** An RFC 5322 Message-ID, with or without its angle brackets */
export const MESSAGE_ID_PATTERN = /^<?[^<>\s@]{1,200}@[^<>\s@]{1,255}>?$/;

/** A delivery status as message trace words it ("Delivered", "Quarantined") */
export const DELIVERY_STATUS_PATTERN = /^[A-Za-z][A-Za-z ]{0,39}$/;

/**
 * A Graph item ID (a message): standard or URL-safe base64 text. Carried,
 * never interpreted; it may enter a request only through `graphPath`.
 */
export const GRAPH_ITEM_ID_PATTERN = /^[A-Za-z0-9+/=_-]{1,512}$/;

/** An Entra directory object ID (a user's mailbox): a GUID */
export const DIRECTORY_ID_PATTERN = /^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$/;

/** Graph IDs of matching copies kept per recipient: the scope a response action may name */
export const MAX_REPORTED_COPY_IDS = 5;

/**
 * Per-copy details a live removal checks (`copyDetails`): tight bounds so a
 * sender cannot inflate the blast-radius answer past its size cap. A value
 * over its bound, or not plain printable ASCII, is omitted (that copy is
 * then not eligible for a live removal), never truncated and compared.
 */
export const MAX_COPY_MESSAGE_ID_LENGTH = 160;
export const MAX_COPY_SENDER_LENGTH = 128;
/** Printable ASCII with no quote or backslash: one byte each in JSON */
export const COPY_TEXT_PATTERN = /^[\x21\x23-\x5b\x5d-\x7e]+$/;
