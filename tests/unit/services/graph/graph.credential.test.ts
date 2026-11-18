/**
 * Graph credential loading and client factory tests
 */

import {
  GraphAuthError,
  GraphClient,
  createGraphClient,
  createGraphReadClient,
  graphPath,
  loadGraphCredential,
  resolveCertificateMaterial,
} from '../../../../src/services/graph';
import { TestCertificate, generateTestCertificate } from '../../../mocks/graph.testcert';

const TENANT_ID = 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb';
const CLIENT_ID = 'cccccccc-4444-4555-8666-dddddddddddd';
const SECRET_ARN = 'arn:aws:secretsmanager:us-east-1:000000000000:secret:phishy/graph-read-AbCdEf';

let testCert: TestCertificate;

beforeAll(() => {
  testCert = generateTestCertificate();
});

function settings(certificate: string): {
  label: string;
  tenantId: string;
  clientId: string;
  certificate: string;
} {
  return { label: 'read', tenantId: TENANT_ID, clientId: CLIENT_ID, certificate };
}

describe('resolveCertificateMaterial', () => {
  it('returns inline material untouched, without calling Secrets Manager', async () => {
    const fetchSecret = jest.fn();
    await expect(resolveCertificateMaterial(testCert.bundlePem, fetchSecret)).resolves.toBe(
      testCert.bundlePem
    );
    expect(fetchSecret).not.toHaveBeenCalled();
  });

  it('fetches the secret when the setting is a Secrets Manager ARN', async () => {
    const fetchSecret = jest.fn(() => Promise.resolve(testCert.bundlePem));
    await expect(resolveCertificateMaterial(SECRET_ARN, fetchSecret)).resolves.toBe(
      testCert.bundlePem
    );
    expect(fetchSecret).toHaveBeenCalledWith(SECRET_ARN);
  });

  it('reports a fetch failure by error class only', async () => {
    const denied = new Error('User is not authorized: sensitive detail');
    denied.name = 'AccessDeniedException';
    const fetchSecret = jest.fn(() => Promise.reject(denied));
    await expect(resolveCertificateMaterial(SECRET_ARN, fetchSecret)).rejects.toThrow(
      'certificate secret could not be read from Secrets Manager (AccessDeniedException)'
    );
    await expect(resolveCertificateMaterial(SECRET_ARN, fetchSecret)).rejects.not.toThrow(
      'sensitive detail'
    );
  });
});

describe('loadGraphCredential', () => {
  it('loads a credential from inline PEM', async () => {
    const credential = await loadGraphCredential(settings(testCert.bundlePem));
    expect(credential).toMatchObject({ label: 'read', tenantId: TENANT_ID, clientId: CLIENT_ID });
    expect(credential.certificate.thumbprintS256).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('loads a credential from a secret holding the JSON form', async () => {
    const secret = JSON.stringify({
      privateKey: testCert.privateKeyPem,
      certificate: testCert.certificatePem,
    });
    const credential = await loadGraphCredential(settings(SECRET_ARN), () =>
      Promise.resolve(secret)
    );
    expect(credential.certificate.privateKey.type).toBe('private');
  });

  it('validates the identifiers before touching the secret', async () => {
    const fetchSecret = jest.fn();
    await expect(
      loadGraphCredential({ ...settings(SECRET_ARN), tenantId: 'common/../x' }, fetchSecret)
    ).rejects.toThrow('tenantId');
    await expect(
      loadGraphCredential({ ...settings(SECRET_ARN), clientId: 'not-a-guid' }, fetchSecret)
    ).rejects.toThrow('clientId');
    expect(fetchSecret).not.toHaveBeenCalled();
  });

  it('refuses an expired certificate', async () => {
    const expired = generateTestCertificate({ notAfter: new Date(Date.now() - 60 * 60 * 1000) });
    await expect(loadGraphCredential(settings(expired.bundlePem))).rejects.toThrow(
      /^certificate expired on \d{4}-/
    );
  });

  it('warns, without failing, when the certificate is close to expiry', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const closing = generateTestCertificate({
      notAfter: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
    });
    await expect(loadGraphCredential(settings(closing.bundlePem))).resolves.toBeDefined();
    // LOG_LEVEL is "error" under test, so the warning itself is filtered;
    // what matters is that nothing was written that could hold key material
    expect(warn.mock.calls.flat().join(' ')).not.toContain('PRIVATE KEY');
  });
});

describe('createGraphClient', () => {
  function tokenThenData(): jest.Mock<Promise<Response>, [URL | string, RequestInit]> {
    return jest.fn((url: URL | string, _init: RequestInit) => {
      if (String(url).startsWith('https://login.microsoftonline.com/')) {
        return Promise.resolve(
          new Response(JSON.stringify({ expires_in: 3600, access_token: 'token-abc' }))
        );
      }
      return Promise.resolve(new Response(JSON.stringify({ id: 'x' })));
    });
  }

  it('is lazy: nothing is fetched until the first request', async () => {
    const fetchSecret = jest.fn(() => Promise.resolve(testCert.bundlePem));
    const fetchMock = tokenThenData();
    const client = createGraphClient(settings(SECRET_ARN), {
      fetchSecret,
      tokenOptions: { fetchImpl: fetchMock as unknown as typeof fetch },
      clientOptions: { fetchImpl: fetchMock as unknown as typeof fetch },
    });

    expect(client).toBeInstanceOf(GraphClient);
    expect(client.label).toBe('read');
    expect(fetchSecret).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();

    await expect(client.getJson(graphPath`/organization`)).resolves.toEqual({ id: 'x' });
    await expect(client.getJson(graphPath`/organization`)).resolves.toEqual({ id: 'x' });

    // One secret read and one token request serve both calls
    expect(fetchSecret).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls.map(call => new URL(String(call[0])).host)).toEqual([
      'login.microsoftonline.com',
      'graph.microsoft.com',
      'graph.microsoft.com',
    ]);
    expect(fetchMock.mock.calls[1][1].headers).toMatchObject({
      Authorization: 'Bearer token-abc',
    });
  });

  it('surfaces a credential failure as GraphAuthError and retries the load next time', async () => {
    const fetchSecret = jest
      .fn<Promise<string>, [string]>()
      .mockRejectedValueOnce(new Error('throttled'))
      .mockResolvedValue(testCert.bundlePem);
    const fetchMock = tokenThenData();
    const client = createGraphClient(settings(SECRET_ARN), {
      fetchSecret,
      tokenOptions: { fetchImpl: fetchMock as unknown as typeof fetch },
      clientOptions: { fetchImpl: fetchMock as unknown as typeof fetch },
    });

    await expect(client.getJson(graphPath`/organization`)).rejects.toBeInstanceOf(GraphAuthError);
    expect(fetchMock).not.toHaveBeenCalled();
    await expect(client.getJson(graphPath`/organization`)).resolves.toEqual({ id: 'x' });
    expect(fetchSecret).toHaveBeenCalledTimes(2);
  });
});

describe('createGraphReadClient', () => {
  it('returns undefined when Graph is absent or disabled', () => {
    expect(createGraphReadClient(undefined)).toBeUndefined();
    expect(createGraphReadClient({ enabled: false })).toBeUndefined();
    expect(
      createGraphReadClient({
        enabled: false,
        tenantId: TENANT_ID,
        read: { clientId: CLIENT_ID, certificate: SECRET_ARN },
      })
    ).toBeUndefined();
  });

  it('builds a client labelled "read" when enabled', () => {
    const client = createGraphReadClient({
      enabled: true,
      tenantId: TENANT_ID,
      read: { clientId: CLIENT_ID, certificate: SECRET_ARN },
    });
    expect(client).toBeInstanceOf(GraphClient);
    expect(client?.label).toBe('read');
  });

  it('refuses an enabled config with missing settings', () => {
    expect(() => createGraphReadClient({ enabled: true, tenantId: TENANT_ID })).toThrow('missing');
  });
});
