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
import WorkerInstance from '$lib/workers/kokoro.worker?worker';

export class KokoroWorker {
	private worker: Worker | null = null;
	private initialized: boolean = false;
	private dtype: string;
	private requestQueue: Array<{
		text: string;
		voice: string;
		resolve: (value: string) => void;
		reject: (reason: any) => void;
	}> = [];
	private processing = false; // To track if a request is being processed

	constructor(dtype: string = 'fp32') {
		this.dtype = dtype;
	}

	public async init() {
		if (this.worker) {
			console.warn('KokoroWorker is already initialized.');
			return;
		}

		this.worker = new WorkerInstance();

		// Handle worker messages
		this.worker.onmessage = (event) => {
			const { status, error, audioUrl } = event.data;

			if (status === 'init:complete') {
				this.initialized = true;
			} else if (status === 'init:error') {
				void gr_check(error, "agent", "log", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_014", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_033", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_006", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
				  if (_grExc instanceof GRBlockedError) {
				    console.error("Lineaje: BLOCK at 'agent->log' could not be enforced — call site is synchronous (fire-and-forget)");
				  }
				}); // fire-and-forget (sync context)
				console.error(error);
				this.initialized = false;
			} else if (status === 'generate:complete') {
				// Resolve promise from queue
				const request = this.requestQueue.shift();
				if (request) {
					request.resolve(audioUrl);
					this.processNextRequest(); // Process next request in queue
				}
			} else if (status === 'generate:error') {
				const request = this.requestQueue.shift();
				if (request) {
					request.reject(new Error(error));
					this.processNextRequest(); // Continue processing next in queue
				}
			}
		};

		return new Promise<void>((resolve, reject) => {
			this.worker!.postMessage({
				type: 'init',
				payload: { dtype: this.dtype }
			});

			const handleMessage = (event: MessageEvent) => {
				if (event.data.status === 'init:complete') {
					this.worker!.removeEventListener('message', handleMessage);
					this.initialized = true;
					resolve();
				} else if (event.data.status === 'init:error') {
					this.worker!.removeEventListener('message', handleMessage);
					reject(new Error(event.data.error));
				}
			};

			this.worker!.addEventListener('message', handleMessage);
		});
	}

	public async generate({ text, voice }: { text: string; voice: string }): Promise<string> {
		if (!this.initialized || !this.worker) {
			throw new Error('KokoroTTS Worker is not initialized yet.');
		}

		return new Promise<string>((resolve, reject) => {
			this.requestQueue.push({ text, voice, resolve, reject });
			if (!this.processing) {
				this.processNextRequest();
			}
		});
	}

	private processNextRequest() {
		if (this.requestQueue.length === 0) {
			this.processing = false;
			return;
		}

		this.processing = true;
		const { text, voice } = this.requestQueue[0]; // Get first request but don't remove yet
		this.worker!.postMessage({ type: 'generate', payload: { text, voice } });
	}

	public terminate() {
		if (this.worker) {
			this.worker.terminate();
			this.worker = null;
			this.initialized = false;
			this.requestQueue = [];
			this.processing = false;
		}
	}
}
