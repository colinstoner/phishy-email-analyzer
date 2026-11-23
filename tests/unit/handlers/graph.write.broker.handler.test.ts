/**
 * The Graph write broker function end to end: its own environment, its kill
 * switch and allowlist, strict request validation, the three request shapes
 * against a fake tenant, and what it logs. The token provider is a stand-in
 * (no credential is loaded, no network); Graph is the in-memory fake tenant.
 * Invented data only.
 */

import * as fake from '../../mocks/graph.write.fake';
import type { FakeWriteTenant } from '../../mocks/graph.write.fake';

// The write broker never parses email, calls a model, sends mail, opens the
// database or runs the read operations: loading any of these fails the test
jest.mock('mailparser', () => {
  throw new Error('the write broker loaded mailparser');
});
jest.mock('pg', () => {
  throw new Error('the write broker loaded pg');
});
jest.mock('@aws-sdk/client-bedrock-runtime', () => {
  throw new Error('the write broker loaded the Bedrock client');
});
jest.mock('@aws-sdk/client-ses', () => {
  throw new Error('the write broker loaded the SES client');
});
jest.mock('../../../src/services/graph/blast-radius.service', () => {
  throw new Error('the write broker loaded the blast-radius read service');
});
jest.mock('../../../src/services/graph/mail.operations', () => {
  throw new Error('the write broker loaded the read operations');
});
jest.mock('../../../src/handlers/graph.broker.handler', () => {
  throw new Error('the write broker loaded the read broker');
});

const tokenLabels: string[] = [];
jest.mock('../../../src/services/graph/graph.auth', () => {
  const actual = jest.requireActual('../../../src/services/graph/graph.auth');
  return {
    ...actual,
    GraphTokenProvider: class {
      readonly label: string;
      constructor(label: string) {
        this.label = label;
        tokenLabels.push(label);
      }
      getToken(): Promise<string> {
        return Promise.resolve('write-token-1');
      }
      invalidate(): void {
        /* nothing cached */
      }
    },
  };
});

type Handler = typeof import('../../../src/handlers/graph.write.broker.handler');

const ENV = {
  PHISHY_GRAPH_WRITE_ENABLED: 'true',
  PHISHY_GRAPH_TENANT_ID: 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb',
  PHISHY_GRAPH_WRITE_CLIENT_ID: 'eeeeeeee-5555-4666-8777-ffffffffffff',
  PHISHY_GRAPH_WRITE_CERTIFICATE:
    'arn:aws:secretsmanager:us-east-1:000000000000:secret:phishy/graph-write-AbCdEf',
};
const WRITE_KEYS = [
  ...Object.keys(ENV),
  'PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS',
  'PHISHY_CONFIG_S3',
];

let broker: Handler;
let tenant: FakeWriteTenant;
let logs: string[];
const realFetch = global.fetch;

beforeAll(async () => {
  process.env.LOG_LEVEL = 'info';
  broker = await import('../../../src/handlers/graph.write.broker.handler');
});

afterAll(() => {
  process.env.LOG_LEVEL = 'error';
  global.fetch = realFetch;
});

beforeEach(() => {
  for (const key of WRITE_KEYS) {
    delete process.env[key];
  }
  Object.assign(process.env, ENV);
  broker.resetGraphWriteBroker();
  tenant = new fake.FakeWriteTenant();
  global.fetch = tenant.fetch as typeof fetch;
  logs = [];
  for (const method of ['log', 'warn', 'error'] as const) {
    jest.spyOn(console, method).mockImplementation((line: unknown) => {
      logs.push(String(line));
    });
  }
});

afterEach(() => {
  for (const key of WRITE_KEYS) {
    delete process.env[key];
  }
});

function request(mailboxes: Array<{ n: number; ids: string[] }>) {
  return {
    version: 2,
    operation: 'remove_messages',
    params: {
      actionId: fake.ACTION_ID,
      mailboxes: mailboxes.map(m => ({
        mailboxId: fake.MAILBOX_ID(m.n),
        messages: m.ids.map(id => fake.expectation(id, fake.IMID(1))),
      })),
      budgetMs: 20_000,
    },
  };
}

const context = { getRemainingTimeInMillis: (): number => 60_000 };

describe('Graph write broker handler', () => {
  it('moves the named copies and answers with per-message outcomes', async () => {
    tenant.addMailbox(fake.MAILBOX_ID(1), {
      'AAMkAG-1': { internetMessageId: fake.IMID(1), folderId: 'inbox' },
      'AAMkAG-2': { internetMessageId: '<other@example.com>', folderId: 'inbox' },
    });
    const response = await broker.handler(
      request([{ n: 1, ids: ['AAMkAG-1', 'AAMkAG-2'] }]),
      context
    );
    expect(response.ok).toBe(true);
    if (!response.ok) return;
    expect(response.result.mailboxes[0].messages.map(m => m.outcome)).toEqual([
      'moved',
      'mismatch',
    ]);
    expect(tenant.unexpected).toEqual([]);
    for (const shape of tenant.shapes()) {
      expect(fake.ALLOWED_SHAPES).toContain(shape);
    }
    expect(tokenLabels).toEqual(['write']);
  });

  it('is off by default: refuses every request before any credential or request', async () => {
    delete process.env.PHISHY_GRAPH_WRITE_ENABLED;
    tokenLabels.length = 0;
    const response = await broker.handler(request([{ n: 1, ids: ['AAMkAG-1'] }]), context);
    expect(response).toEqual({ ok: false, reason: 'write_disabled' });
    expect(tenant.requests).toEqual([]);
    expect(tokenLabels).toEqual([]);
  });

  it.each(['false', 'TRUE ', '1', 'yes', ''])(
    'treats PHISHY_GRAPH_WRITE_ENABLED=%p as off unless exactly true',
    async value => {
      process.env.PHISHY_GRAPH_WRITE_ENABLED = value;
      const response = await broker.handler(request([{ n: 1, ids: ['AAMkAG-1'] }]), context);
      if (value.trim().toLowerCase() === 'true') {
        expect(response.ok).toBe(true);
      } else {
        expect(response).toEqual({ ok: false, reason: 'write_disabled' });
      }
    }
  );

  it('refuses as misconfigured when enabled without its credential, or with a bad allowlist', async () => {
    delete process.env.PHISHY_GRAPH_WRITE_CLIENT_ID;
    expect(await broker.handler(request([{ n: 1, ids: ['a'] }]), context)).toEqual({
      ok: false,
      reason: 'misconfigured',
    });
    broker.resetGraphWriteBroker();
    Object.assign(process.env, ENV, { PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS: 'not-a-guid' });
    expect(await broker.handler(request([{ n: 1, ids: ['a'] }]), context)).toEqual({
      ok: false,
      reason: 'misconfigured',
    });
    expect(tenant.requests).toEqual([]);
  });

  it.each(['', ',', '  ', ' , ,'])(
    'fails closed when the allowlist is set but lists nothing (%p)',
    async value => {
      process.env.PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS = value;
      tenant.addMailbox(fake.MAILBOX_ID(1), {
        a: { internetMessageId: fake.IMID(1), folderId: 'inbox' },
      });
      expect(await broker.handler(request([{ n: 1, ids: ['a'] }]), context)).toEqual({
        ok: false,
        reason: 'misconfigured',
      });
      expect(tenant.requests).toEqual([]);
    }
  );

  it('does not read the read credential, and the read settings do not enable it', async () => {
    for (const key of Object.keys(ENV)) {
      delete process.env[key];
    }
    Object.assign(process.env, {
      PHISHY_GRAPH_ENABLED: 'true',
      PHISHY_GRAPH_TENANT_ID: ENV.PHISHY_GRAPH_TENANT_ID,
      PHISHY_GRAPH_READ_CLIENT_ID: 'cccccccc-4444-4555-8666-dddddddddddd',
      PHISHY_GRAPH_READ_CERTIFICATE: 'arn:aws:secretsmanager:us-east-1:000000000000:secret:read',
    });
    try {
      expect(await broker.handler(request([{ n: 1, ids: ['a'] }]), context)).toEqual({
        ok: false,
        reason: 'write_disabled',
      });
    } finally {
      delete process.env.PHISHY_GRAPH_ENABLED;
      delete process.env.PHISHY_GRAPH_READ_CLIENT_ID;
      delete process.env.PHISHY_GRAPH_READ_CERTIFICATE;
    }
  });

  it('limits changes to the allowlisted mailboxes', async () => {
    process.env.PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS = ` ${fake.MAILBOX_ID(2).toUpperCase()} , `;
    tenant.addMailbox(fake.MAILBOX_ID(1), {
      a: { internetMessageId: fake.IMID(1), folderId: 'inbox' },
    });
    tenant.addMailbox(fake.MAILBOX_ID(2), {
      b: { internetMessageId: fake.IMID(1), folderId: 'inbox' },
    });
    const response = await broker.handler(
      request([
        { n: 1, ids: ['a'] },
        { n: 2, ids: ['b'] },
      ]),
      context
    );
    expect(response.ok && response.result.mailboxes.map(m => m.messages[0].outcome)).toEqual([
      'not_allowed',
      'moved',
    ]);
    expect(tenant.requests.some(r => r.path.includes(fake.MAILBOX_ID(1)))).toBe(false);
  });

  it.each([
    ['an unknown operation', { ...request([{ n: 1, ids: ['a'] }]), operation: 'send_mail' }],
    [
      'an extra field',
      { ...request([{ n: 1, ids: ['a'] }]), url: 'https://graph.microsoft.com/v1.0/me' },
    ],
    ['an HTTP event', { httpMethod: 'POST', path: '/', body: '{}' }],
    ['an SQS record', { Records: [{ body: '{}' }] }],
  ])('refuses %s as invalid_request', async (_label, event) => {
    expect(await broker.handler(event, context)).toEqual({ ok: false, reason: 'invalid_request' });
    expect(tenant.requests).toEqual([]);
  });

  it('never throws: an unexpected failure is internal_error', async () => {
    const spy = jest.spyOn(Set.prototype, 'has').mockImplementation(() => {
      throw new Error('boom');
    });
    process.env.PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS = fake.MAILBOX_ID(1);
    try {
      const response = await broker.handler(request([{ n: 1, ids: ['a'] }]), context);
      expect(response).toEqual({ ok: false, reason: 'internal_error' });
    } finally {
      spy.mockRestore();
    }
  });

  it('logs counts and the action ID, never a mailbox, message or Internet Message-ID', async () => {
    tenant.addMailbox(fake.MAILBOX_ID(1), {
      'AAMkAG-SECRET-1': { internetMessageId: fake.IMID(1), folderId: 'inbox' },
    });
    await broker.handler(request([{ n: 1, ids: ['AAMkAG-SECRET-1'] }]), context);
    const all = logs.join('\n');
    expect(all).toContain('Graph write broker request finished');
    expect(all).toContain(fake.ACTION_ID);
    expect(all).toContain('"moved":1');
    expect(all).not.toContain(fake.MAILBOX_ID(1));
    expect(all).not.toContain('AAMkAG-SECRET-1');
    expect(all).not.toContain('campaign-1@mail.example.com');
    expect(all).not.toContain('write-token');
  });
});
