// Copyright (c) Lineaje, Inc. All rights reserved.
// Lineaje guardrail helper — inlined once per file (see _import_hint); no npm
// package to install. gr_check() POSTs to GR_SERVICE_URL + "/enforce" and fails
// open (returns `data` unchanged) unless a policy deliberately blocks it
// (GRBlockedError, only on GR_BLOCK_MODE=enforce + an HTTP 403).
type GrEnv = Record<string, string | undefined>;
const _env: GrEnv = ((globalThis as any).process?.env ?? {}) as GrEnv; // Lineaje: env lookup shim (works in Node and browser bundles)

export class GRBlockedError extends Error {
  policyId: string;
  reason: string;

  constructor(policyId: string, reason: string) {
    super(`Guardrail block for policy '${policyId}': ${reason}`);
    this.name = "GRBlockedError";
    this.policyId = policyId;
    this.reason = reason;
  }
}

export async function gr_check(
  data: unknown,
  sourceType: string,
  destinationType: string,
  tenantId: string = "",
  timeoutMs: number = 5000,
  context: Record<string, string | undefined> = {},
): Promise<unknown> {
  const url = _env["GR_SERVICE_URL"] || "";
  if (!url) {
    return data; // fail-open: GR_SERVICE_URL not configured
  }

  const tid = tenantId || _env["GR_TENANT_ID"] || "";
  const bearer = _env["GR_BEARER_TOKEN"] || _env["LINEAJE_PAT_TOKEN"] || _env["LINEAJE_PAT"] || "";
  const hopLabel = `${sourceType}->${destinationType}`;
  const paramsKey = destinationType === "agent" ? "out_params" : "in_params";

  const body: Record<string, unknown> = {
    source_type: sourceType,
    destination_type: destinationType,
    [paramsKey]: { data },
  };
  for (const [k, v] of Object.entries(context)) {
    if (v) {
      body[k] = v;
    }
  }
  if (tid) {
    body["tenant_id"] = tid;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let resp: Response;
  try {
    resp = await fetch(url.replace(/\/+$/, "") + "/enforce", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + bearer,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (exc) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (${exc}) — failing open`,
    );
    return data;
  } finally {
    clearTimeout(timer);
  }

  if (resp.status === 403) {
    let detail: any = {};
    try {
      const errBody: any = await resp.json();
      detail = errBody?.detail ?? {};
    } catch {
      detail = {};
    }
    const blockedBy = detail.blocked_by ?? [];
    const policyId = blockedBy[0]?.policy_id ?? "unknown";
    const reason = detail.message ?? "Request denied by policy enforcement.";
    console.warn(
      `gr_client[${hopLabel}]: BLOCKED by policy=${policyId} — ${reason}`,
    );
    if ((_env["GR_BLOCK_MODE"] || "enforce").toLowerCase() === "audit") {
      return data;
    }
    throw new GRBlockedError(policyId, reason);
  }

  if (!resp.ok) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (HTTP ${resp.status}) — failing open`,
    );
    return data;
  }

  let result: any;
  try {
    result = await resp.json();
  } catch (exc) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (${exc}) — failing open`,
    );
    return data;
  }

  if (result?.status === "escalate") {
    console.warn(
      `gr_client[${hopLabel}]: escalation flagged — passing through for human review`,
    );
  }

  return result?.result?.data ?? data;
}
/**
 * Shared helpers for managing system-level connections.
 * Used by both the admin settings UI and the desktop event handler
 * to ensure consistent add/remove logic.
 */

import { getOpenAIConfig, updateOpenAIConfig } from '$lib/apis/openai';
import { getTerminalServerConnections, setTerminalServerConnections } from '$lib/apis/configs';

// ─── OpenAI Connections ─────────────────────────────────

/**
 * Add an OpenAI-compatible API connection at the system level.
 * Mirrors the logic in admin/Settings/Connections.svelte.
 */
export const addOpenAIConnection = async (
	token: string,
	connection: { url: string; key?: string; config?: object }
) => {
	const current = await getOpenAIConfig(token);
	const urls = current?.OPENAI_API_BASE_URLS ?? [];
	const keys = current?.OPENAI_API_KEYS ?? [];
	const configs = current?.OPENAI_API_CONFIGS ?? {};

	const normalizedUrl = connection.url.replace(/\/$/, '');

	// Don't add duplicates
	if (urls.map((u: string) => u.replace(/\/$/, '')).includes(normalizedUrl)) {
		return current;
	}

	urls.push(normalizedUrl);
	keys.push(connection.key ?? '');
	if (connection.config) {
		configs[(urls.length - 1).toString()] = connection.config;
	}

	return await updateOpenAIConfig(token, {
		ENABLE_OPENAI_API: current?.ENABLE_OPENAI_API ?? true,
		OPENAI_API_BASE_URLS: urls,
		OPENAI_API_KEYS: keys,
		OPENAI_API_CONFIGS: configs
	});
};

/**
 * Remove an OpenAI-compatible API connection by URL at the system level.
 * Re-indexes OPENAI_API_CONFIGS to match the admin delete pattern.
 */
export const removeOpenAIConnection = async (token: string, url: string) => {
	const current = await getOpenAIConfig(token);
	const urls: string[] = current?.OPENAI_API_BASE_URLS ?? [];
	const keys: string[] = current?.OPENAI_API_KEYS ?? [];
	const configs: Record<string, any> = current?.OPENAI_API_CONFIGS ?? {};

	const normalizedUrl = url.replace(/\/$/, '');
	const idx = urls.findIndex((u: string) => u.replace(/\/$/, '') === normalizedUrl);
	if (idx === -1) return current;

	const newUrls = urls.filter((_: string, i: number) => i !== idx);
	const newKeys = keys.filter((_: string, i: number) => i !== idx);

	// Re-index configs (mirrors admin/Settings/Connections.svelte onDelete)
	const newConfigs: Record<string, any> = {};
	newUrls.forEach((_: string, newIdx: number) => {
		newConfigs[newIdx] = configs[newIdx < idx ? newIdx : newIdx + 1];
	});

	return await updateOpenAIConfig(token, {
		ENABLE_OPENAI_API: current?.ENABLE_OPENAI_API ?? true,
		OPENAI_API_BASE_URLS: newUrls,
		OPENAI_API_KEYS: newKeys,
		OPENAI_API_CONFIGS: newConfigs
	});
};

// ─── Terminal Server Connections ────────────────────────

/**
 * Add a terminal server connection at the system level.
 * Mirrors the logic in admin/Settings/Integrations.svelte.
 */
export const addTerminalConnection = async (
	token: string,
	connection: { url: string; key?: string; name?: string; auth_type?: string }
) => {
	const current = await getTerminalServerConnections(token);
	const servers = current?.TERMINAL_SERVER_CONNECTIONS ?? [];

	// Don't add duplicates
	if (servers.find((s: any) => s.url === connection.url)) {
		void gr_check(current, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
		  if (_grExc instanceof GRBlockedError) {
		    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
		  }
		}); // fire-and-forget (sync context)
		return current;
	}

	servers.push({
		url: connection.url,
		key: connection.key ?? '',
		auth_type: connection.auth_type ?? 'bearer',
		name: connection.name ?? 'Open Terminal',
		enabled: true
	});

	return await setTerminalServerConnections(token, {
		TERMINAL_SERVER_CONNECTIONS: servers
	});
};

/**
 * Remove a terminal server connection by URL at the system level.
 */
export const removeTerminalConnection = async (token: string, url: string) => {
	const current = await getTerminalServerConnections(token);
	const servers = current?.TERMINAL_SERVER_CONNECTIONS ?? [];

	const filtered = servers.filter((s: any) => s.url !== url);
	if (filtered.length === servers.length) return current; // nothing to remove

	return await setTerminalServerConnections(token, {
		TERMINAL_SERVER_CONNECTIONS: filtered
	});
};
