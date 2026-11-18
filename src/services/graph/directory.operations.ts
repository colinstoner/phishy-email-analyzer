/**
 * Read-only directory operations on Microsoft Graph: users (to learn who
 * owns a mailbox) and subscribed licences (to learn which Microsoft
 * capabilities the tenant has). GET only; fixed endpoints; bounded results.
 */

import { z } from 'zod';
import { GraphClient } from './graph.client';
import { graphPath } from './graph.request';
import { BoundedResult, parseItems, resolveMaxItems } from './operations.common';

const USERS_PATH = graphPath`/users`;
const SKUS_PATH = graphPath`/subscribedSkus`;

const USER_PAGE_SIZE = 999;
const DEFAULT_MAX_USERS = 5000;
const MAX_USERS = 50000;
const MAX_SKUS = 500;

const UserSchema = z.object({
  id: z.string().min(1),
  userPrincipalName: z.string().nullish(),
  mail: z.string().nullish(),
  userType: z.string().nullish(),
  accountEnabled: z.boolean().nullish(),
  assignedPlans: z
    .array(z.object({ service: z.string().nullish(), capabilityStatus: z.string().nullish() }))
    .nullish(),
});

export interface DirectoryUser {
  id: string;
  userPrincipalName?: string;
  /** Primary SMTP address; absent for accounts without one */
  mail?: string;
  /** `Member` or `Guest` */
  userType?: string;
  accountEnabled?: boolean;
  /**
   * True when the user holds an enabled Exchange service plan. The nearest
   * documented signal to "has an Exchange Online mailbox"; shared mailboxes
   * are unlicensed and will read false.
   */
  hasExchangePlan: boolean;
}

/**
 * List users with the fields that matter for mailbox lookups.
 * `GET /users?$select=id,userPrincipalName,mail,userType,accountEnabled,assignedPlans`
 * (application permission `User.Read.All`).
 */
export async function listUsers(
  client: GraphClient,
  options: { maxItems?: number } = {}
): Promise<BoundedResult<DirectoryUser>> {
  const maxItems = resolveMaxItems(options.maxItems, DEFAULT_MAX_USERS, MAX_USERS);
  const top = Math.min(maxItems, USER_PAGE_SIZE);
  const result = await client.getPaged(USERS_PATH, {
    query: {
      select: ['id', 'userPrincipalName', 'mail', 'userType', 'accountEnabled', 'assignedPlans'],
      top,
    },
    maxItems,
    maxPages: Math.ceil(maxItems / top),
  });
  return {
    items: parseItems(client, USERS_PATH, UserSchema, result.items).map(user => ({
      id: user.id,
      userPrincipalName: user.userPrincipalName ?? undefined,
      mail: user.mail ?? undefined,
      userType: user.userType ?? undefined,
      accountEnabled: user.accountEnabled ?? undefined,
      hasExchangePlan: (user.assignedPlans ?? []).some(
        plan => plan.service === 'exchange' && plan.capabilityStatus === 'Enabled'
      ),
    })),
    truncated: result.truncated,
  };
}

const SkuSchema = z.object({
  skuPartNumber: z.string().nullish(),
  consumedUnits: z.number().nullish(),
  prepaidUnits: z.object({ enabled: z.number().nullish() }).nullish(),
  servicePlans: z.array(z.object({ servicePlanName: z.string().nullish() })).nullish(),
});

export interface SubscribedSku {
  skuPartNumber: string;
  /** Licences assigned to users */
  consumedUnits: number;
  /** Licences purchased and enabled */
  enabledUnits: number;
  servicePlanNames: string[];
}

/** Service plan names behind each capability flag */
export const CAPABILITY_SERVICE_PLANS = {
  defenderForOffice365Plan1: 'ATP_ENTERPRISE',
  defenderForOffice365Plan2: 'THREAT_INTELLIGENCE',
  entraIdP1: 'AAD_PREMIUM',
  entraIdP2: 'AAD_PREMIUM_P2',
} as const;

export type LicenceCapability = keyof typeof CAPABILITY_SERVICE_PLANS;
export type LicenceCapabilities = Record<LicenceCapability, boolean>;

export interface SubscribedSkuSummary {
  skus: SubscribedSku[];
  /** A capability is true only when a SKU containing its plan has assigned units */
  capabilities: LicenceCapabilities;
  truncated: boolean;
}

/** Derive capability flags from SKUs: plan present **and** licences assigned */
export function summarizeCapabilities(skus: SubscribedSku[]): LicenceCapabilities {
  const has = (plan: string): boolean =>
    skus.some(sku => sku.consumedUnits > 0 && sku.servicePlanNames.includes(plan));
  return {
    defenderForOffice365Plan1: has(CAPABILITY_SERVICE_PLANS.defenderForOffice365Plan1),
    defenderForOffice365Plan2: has(CAPABILITY_SERVICE_PLANS.defenderForOffice365Plan2),
    entraIdP1: has(CAPABILITY_SERVICE_PLANS.entraIdP1),
    entraIdP2: has(CAPABILITY_SERVICE_PLANS.entraIdP2),
  };
}

/**
 * The tenant's subscribed SKUs, summarized into capability flags.
 * `GET /subscribedSkus` (application permission `LicenseAssignment.Read.All`,
 * least privileged; `Organization.Read.All` also works).
 */
export async function listSubscribedSkus(client: GraphClient): Promise<SubscribedSkuSummary> {
  const result = await client.getPaged(SKUS_PATH, { maxItems: MAX_SKUS, maxPages: 2 });
  const skus = parseItems(client, SKUS_PATH, SkuSchema, result.items).map(sku => ({
    skuPartNumber: sku.skuPartNumber ?? '',
    consumedUnits: sku.consumedUnits ?? 0,
    enabledUnits: sku.prepaidUnits?.enabled ?? 0,
    servicePlanNames: (sku.servicePlans ?? [])
      .map(plan => plan.servicePlanName)
      .filter((name): name is string => typeof name === 'string'),
  }));
  return { skus, capabilities: summarizeCapabilities(skus), truncated: result.truncated };
}
