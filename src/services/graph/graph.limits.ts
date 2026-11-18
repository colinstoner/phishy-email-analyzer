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
