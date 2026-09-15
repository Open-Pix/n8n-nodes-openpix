import { createHmac } from 'crypto';
import { IWebhookFunctions } from 'n8n-workflow';

import { OpenPixTrigger } from '../OpenPixTrigger.node';

const hmacSecretKey = 'openpix_g98Nj/oCocUi4mBu/AP5avmbLEmk=';

const payload = JSON.stringify({
  event: 'OPENPIX:CHARGE_COMPLETED',
  charge: {
    status: 'COMPLETED',
    value: 10000,
    correlationID: 'abc-123',
  },
});

const sign = (body: string, key = hmacSecretKey) =>
  createHmac('sha1', key).update(Buffer.from(body)).digest('base64');

type BuildContextInput = {
  staticData?: Record<string, unknown>;
  publicKey?: string;
  headers?: Record<string, string>;
  rawBody?: Buffer | string;
  body?: unknown;
};

const buildContext = ({
  staticData = {},
  publicKey = '',
  headers = {},
  rawBody,
  body,
}: BuildContextInput) => {
  const status = jest.fn().mockReturnThis();
  const json = jest.fn().mockReturnThis();

  const context = {
    getRequestObject: () => ({ headers, rawBody, body }),
    getResponseObject: () => ({ status, json }),
    getWorkflowStaticData: () => staticData,
    getNodeParameter: (name: string, fallback: unknown) =>
      name === 'webhookPublicKey' ? publicKey : fallback,
    helpers: {
      returnJsonArray: (data: unknown) => [{ json: data }],
    },
  } as unknown as IWebhookFunctions;

  return { context, status, json };
};

const runWebhook = (input: BuildContextInput) => {
  const { context, status, json } = buildContext(input);

  return {
    result: new OpenPixTrigger().webhook.call(context),
    status,
    json,
  };
};

describe('OpenPixTrigger webhook', () => {
  it('should accept a genuine webhook and output the parsed body', async () => {
    const { result } = runWebhook({
      staticData: { hmacSecretKey },
      headers: { 'x-openpix-signature': sign(payload) },
      rawBody: Buffer.from(payload),
      body: JSON.parse(payload),
    });

    await expect(result).resolves.toEqual({
      workflowData: [[{ json: JSON.parse(payload) }]],
    });
  });

  it('should reject a forged webhook with 401', async () => {
    const forged = JSON.stringify({
      event: 'OPENPIX:CHARGE_COMPLETED',
      charge: { status: 'COMPLETED', value: 10000000 },
    });

    const { result, status, json } = runWebhook({
      staticData: { hmacSecretKey },
      rawBody: Buffer.from(forged),
      body: JSON.parse(forged),
    });

    await expect(result).resolves.toEqual({ noWebhookResponse: true });

    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({ message: 'Invalid webhook signature' });
  });

  it('should reject a signature computed with another secret', async () => {
    const { result, status } = runWebhook({
      staticData: { hmacSecretKey },
      headers: { 'x-openpix-signature': sign(payload, 'another_secret') },
      rawBody: Buffer.from(payload),
      body: JSON.parse(payload),
    });

    await expect(result).resolves.toEqual({ noWebhookResponse: true });

    expect(status).toHaveBeenCalledWith(401);
  });

  it('should verify against the re-serialized body when rawBody is missing', async () => {
    const { result } = runWebhook({
      staticData: { hmacSecretKey },
      headers: { 'x-openpix-signature': sign(payload) },
      body: JSON.parse(payload),
    });

    await expect(result).resolves.toEqual({
      workflowData: [[{ json: JSON.parse(payload) }]],
    });
  });

  it('should keep accepting webhooks when no secret and no public key are set', async () => {
    const { result } = runWebhook({
      rawBody: Buffer.from(payload),
      body: JSON.parse(payload),
    });

    await expect(result).resolves.toEqual({
      workflowData: [[{ json: JSON.parse(payload) }]],
    });
  });

  it('should fall back to the public key when there is no HMAC secret', async () => {
    const { result, status } = runWebhook({
      publicKey: 'not-a-key',
      headers: { 'x-webhook-signature': 'whatever' },
      rawBody: Buffer.from(payload),
      body: JSON.parse(payload),
    });

    await expect(result).resolves.toEqual({ noWebhookResponse: true });

    expect(status).toHaveBeenCalledWith(401);
  });
});
