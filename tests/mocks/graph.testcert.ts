/**
 * Throwaway signing material for Microsoft Graph tests.
 *
 * Generates an RSA key pair and a minimal self-signed X.509 certificate in
 * memory, so no key or certificate file is ever committed. Node has no
 * certificate-issuing API, so the certificate's DER is assembled by hand —
 * just enough ASN.1 for `crypto.X509Certificate` to parse it.
 */

import { KeyObject, generateKeyPairSync, sign } from 'crypto';

export interface TestCertificate {
  privateKey: KeyObject;
  publicKey: KeyObject;
  privateKeyPem: string;
  certificatePem: string;
  /** Private key followed by certificate, as an operator would store it */
  bundlePem: string;
  certificateDer: Buffer;
}

function tlv(tag: number, content: Buffer): Buffer {
  const length = content.length;
  let header: Buffer;
  if (length < 0x80) {
    header = Buffer.from([tag, length]);
  } else if (length < 0x100) {
    header = Buffer.from([tag, 0x81, length]);
  } else {
    header = Buffer.from([tag, 0x82, length >> 8, length & 0xff]);
  }
  return Buffer.concat([header, content]);
}

const sequence = (...items: Buffer[]): Buffer => tlv(0x30, Buffer.concat(items));

function utcTime(date: Date): Buffer {
  const text = date.toISOString().replace(/[-:T]/g, '').slice(2, 14);
  return tlv(0x17, Buffer.from(`${text}Z`, 'ascii'));
}

/** sha256WithRSAEncryption (1.2.840.113549.1.1.11) with NULL parameters */
const SIGNATURE_ALGORITHM = sequence(
  Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
  Buffer.from([0x05, 0x00])
);

function distinguishedName(commonName: string): Buffer {
  const attribute = sequence(
    Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]), // commonName (2.5.4.3)
    tlv(0x0c, Buffer.from(commonName, 'utf8'))
  );
  return sequence(tlv(0x31, attribute));
}

export function pemEncode(label: string, der: Buffer): string {
  const body = der.toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN ${label}-----\n${body.trimEnd()}\n-----END ${label}-----\n`;
}

/**
 * Generate a key pair and a self-signed certificate for it
 */
export function generateTestCertificate(
  options: { commonName?: string; notAfter?: Date } = {}
): TestCertificate {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

  const notBefore = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const notAfter = options.notAfter ?? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  const name = distinguishedName(options.commonName ?? 'phishy-graph-test.example.com');

  const tbsCertificate = sequence(
    tlv(0x02, Buffer.from([0x01])), // serialNumber
    SIGNATURE_ALGORITHM,
    name, // issuer
    sequence(utcTime(notBefore), utcTime(notAfter)),
    name, // subject
    publicKey.export({ type: 'spki', format: 'der' })
  );
  const signature = sign('sha256', tbsCertificate, privateKey);
  const certificateDer = sequence(
    tbsCertificate,
    SIGNATURE_ALGORITHM,
    tlv(0x03, Buffer.concat([Buffer.from([0x00]), signature]))
  );

  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const certificatePem = pemEncode('CERTIFICATE', certificateDer);

  return {
    privateKey,
    publicKey,
    privateKeyPem,
    certificatePem,
    bundlePem: `${privateKeyPem}${certificatePem}`,
    certificateDer,
  };
}
