import {
  IHookFunctions,
  ILoadOptionsFunctions,
  INodePropertyOptions,
  INodeType,
  INodeTypeDescription,
  IWebhookFunctions,
  IWebhookResponseData,
  NodeApiError,
} from 'n8n-workflow';
import { apiRequest } from './transport';
import {
  HMAC_SIGNATURE_HEADER,
  RSA_SIGNATURE_HEADER,
  verifyHmacSignature,
  verifyRsaSignature,
} from './verifySignature';

type WebhookRequest = {
  body?: unknown;
  rawBody?: Buffer | string;
};

const getRawBody = (req: WebhookRequest): Buffer => {
  const { rawBody } = req;

  if (Buffer.isBuffer(rawBody)) {
    return rawBody;
  }

  if (typeof rawBody === 'string') {
    return Buffer.from(rawBody);
  }

  return Buffer.from(JSON.stringify(req.body ?? {}));
};

export class OpenPixTrigger implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'OpenPix Trigger',
    name: 'openpixTrigger',
    icon: 'file:openpix.svg',
    group: ['trigger'],
    version: 1,
    subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
    description: 'Handle OpenPix Events via Webhook',

    defaults: {
      name: 'OpenPix Trigger',
    },
    inputs: [],
    outputs: ['main'],
    credentials: [
      {
        name: 'openpixApi',
        required: true,
      },
    ],
    requestDefaults: {
      baseURL: 'https://api.openpix.com.br/api',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'n8n',
      },
    },
    webhooks: [
      {
        name: 'default',
        httpMethod: 'POST',
        responseMode: 'onReceived',
        path: 'webhook',
      },
    ],
    properties: [
      {
        displayName: 'Event Names or Name or ID',
        name: 'events',
        type: 'options',
        required: true,
        default: '',
        description:
          'The event to listen to. Choose from the list, or specify IDs using an <a href="https://docs.n8n.io/code-examples/expressions/">expression</a>. Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code-examples/expressions/">expression</a>. Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code/expressions/">expression</a>.',
        typeOptions: {
          loadOptionsMethod: 'getEvents',
        },
        options: [],
      },
      {
        displayName: 'Webhook Public Key',
        name: 'webhookPublicKey',
        type: 'string',
        default: '',
        typeOptions: {
          password: true,
        },
        description:
          'OpenPix public key used to verify the x-webhook-signature header. Only needed for webhooks created outside this node — webhooks created here are verified automatically with their HMAC secret.',
      },
    ],
  };

  methods = {
    loadOptions: {
      // Get all the events types to display them to user so that he can
      // select them easily
      async getEvents(
        this: ILoadOptionsFunctions,
      ): Promise<INodePropertyOptions[]> {
        // TODO: Check if make sense the * event
        const returnData: INodePropertyOptions[] = [];
        let response;

        try {
          const endpoint = '/webhook/events';
          response = await apiRequest.call(this, 'GET', endpoint);
        } catch (error) {
          throw new NodeApiError(this.getNode(), error);
        }

        for (const event of response.events) {
          const eventName = event.name;
          const eventId = event.name;
          // TODO: Add description
          const eventDescription = event.name;

          returnData.push({
            name: eventName,
            value: eventId,
            description: eventDescription,
          });
        }

        return returnData;
      },
    },
  };
  webhookMethods = {
    default: {
      async checkExists(this: IHookFunctions): Promise<boolean> {
        const webhookUrl = this.getNodeWebhookUrl('default');

        let result;

        try {
          result = await apiRequest.call(
            this,
            'GET',
            '/webhook',
            {},
            {
              url: webhookUrl,
            },
          );
        } catch (error) {
          throw new NodeApiError(this.getNode(), error);
        }

        const { webhooks } = result;

        if (webhooks.length) {
          const [webhook] = webhooks;
          const webhookData = this.getWorkflowStaticData('node');

          webhookData.webhookId = webhook.id;
          webhookData.hmacSecretKey = webhook.hmacSecretKey;

          return true;
        }

        return false;
      },

      async create(this: IHookFunctions): Promise<boolean> {
        const webhookUrl = this.getNodeWebhookUrl('default');
        const events = this.getNodeParameter('events', []) as string[];
        const body = {
          name: 'N8N Webhook',
          url: webhookUrl,
          event: events,
          isActive: true,
        };

        let result;

        try {
          result = await apiRequest.call(
            this,
            'POST',
            '/webhook?validate=false',
            {
              webhook: body,
            },
          );
        } catch (error) {
          throw new NodeApiError(this.getNode(), error);
        }

        const { webhook } = result;

        if (webhook.id === undefined) {
          return false;
        }

        const webhookData = this.getWorkflowStaticData('node');
        webhookData.webhookId = webhook.id as string;
        webhookData.hmacSecretKey = webhook.hmacSecretKey as string;

        return true;
      },

      async delete(this: IHookFunctions): Promise<boolean> {
        const webhookData = this.getWorkflowStaticData('node');

        if (webhookData.webhookId !== undefined) {
          try {
            await apiRequest.call(
              this,
              'DELETE',
              `/webhook/${webhookData.webhookId}`,
              {},
            );
          } catch (error) {
            return false;
          }

          delete webhookData.webhookId;
          delete webhookData.hmacSecretKey;
        }

        return true;
      },
    },
  };

  async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
    const req = this.getRequestObject();
    const webhookData = this.getWorkflowStaticData('node');

    const hmacSecretKey = webhookData.hmacSecretKey as string | undefined;
    const publicKey = this.getNodeParameter('webhookPublicKey', '') as string;

    if (hmacSecretKey || publicKey) {
      const rawBody = getRawBody(req);
      const headers = req.headers as Record<string, string | undefined>;

      const isValid = hmacSecretKey
        ? verifyHmacSignature({
            hmacSecretKey,
            rawBody,
            signature: headers[HMAC_SIGNATURE_HEADER],
          })
        : verifyRsaSignature({
            publicKey,
            rawBody,
            signature: headers[RSA_SIGNATURE_HEADER],
          });

      if (!isValid) {
        const res = this.getResponseObject();

        res.status(401).json({ message: 'Invalid webhook signature' });

        return {
          noWebhookResponse: true,
        };
      }
    }

    return {
      workflowData: [this.helpers.returnJsonArray(req.body)],
    };
  }
}
