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
type MessageListener = (event: MessageEvent) => void;
type ErrorListener = (event: Event) => void;
type QueuedMessage = { message: unknown; transfer: Transferable[] };

const sandboxScript = String.raw`
(function () {
	let pyodide = null;
	let pyodideReady = null;
	let stdout = null;
	let stderr = null;

	function post(message, transfer) {
		parent.postMessage(message, '*', transfer || []);
	}

	async function loadRuntime(packages) {
		stdout = null;
		stderr = null;
		pyodide = await loadPyodide({
			indexURL: self.__PYODIDE_INDEX_URL__ || '/pyodide/',
			stdout: function (text) {
				stdout = stdout ? stdout + text + '\n' : text + '\n';
			},
			stderr: function (text) {
				stderr = stderr ? stderr + text + '\n' : text + '\n';
			},
			packages: ['micropip']
		});
		pyodide.FS.mkdirTree('/mnt/uploads');
		await pyodide.pyimport('micropip').install(packages || []);
	}

	async function ensureRuntime(packages) {
		if (!pyodideReady) pyodideReady = loadRuntime(packages || []);
		await pyodideReady;
		if (packages && packages.length > 0) {
			await pyodide.pyimport('micropip').install(packages);
		}
	}

	function ensureDir(dir) {
		try {
			pyodide.FS.stat(dir);
		} catch {
			pyodide.FS.mkdirTree(dir);
		}
	}

	function upload(files, dir) {
		dir = dir || '/mnt/uploads';
		ensureDir(dir);
		for (const file of files || []) {
			pyodide.FS.writeFile(dir + '/' + file.name, new Uint8Array(file.data));
		}
	}

	function list(path) {
		const entries = [];
		try {
			const names = pyodide.FS.readdir(path).filter(function (name) {
				return name !== '.' && name !== '..';
			});
			for (const name of names) {
				try {
					const stat = pyodide.FS.stat(path + '/' + name);
					const isDir = pyodide.FS.isDir(stat.mode);
					entries.push({ name: name, type: isDir ? 'directory' : 'file', size: isDir ? 0 : stat.size });
				} catch {}
			}
		} catch {}
		void gr_check(entries, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
		  if (_grExc instanceof GRBlockedError) {
		    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
		  }
		}); // fire-and-forget (sync context)
		return entries;
	}

	function remove(path) {
		try {
			const stat = pyodide.FS.stat(path);
			if (!pyodide.FS.isDir(stat.mode)) {
				pyodide.FS.unlink(path);
				return;
			}
			const names = pyodide.FS.readdir(path).filter(function (name) {
				return name !== '.' && name !== '..';
			});
			for (const name of names) remove(path + '/' + name);
			pyodide.FS.rmdir(path);
		} catch {}
	}

	function clean(value) {
		try {
			if (value == null) return null;
			if (['string', 'number', 'boolean'].includes(typeof value)) return value;
			if (typeof value === 'bigint') return value.toString();
			if (Array.isArray(value)) return value.map(clean);
			if (typeof value.toJs === 'function') return clean(value.toJs());
			if (typeof value === 'object') {
				const out = {};
				for (const key in value) {
					if (Object.prototype.hasOwnProperty.call(value, key)) out[key] = clean(value[key]);
				}
				void gr_check(out, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
				  if (_grExc instanceof GRBlockedError) {
				    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
				  }
				}); // fire-and-forget (sync context)
				return out;
			}
			return JSON.stringify(value);
		} catch (error) {
			return '[processResult error]: ' + (error && error.message ? error.message : String(error));
		}
	}

	async function patchMatplotlib() {
		await pyodide.runPythonAsync([
			'import base64',
			'import os',
			'from io import BytesIO',
			'os.environ["MPLBACKEND"] = "AGG"',
			'import matplotlib.pyplot',
			'_old_show = matplotlib.pyplot.show',
			'assert _old_show, "matplotlib.pyplot.show"',
			'def show(*, block=None):',
			// String.raw keeps \t as-is; the sandbox's JS parser turns it into a real tab
			'\tbuf = BytesIO()',
			'\tmatplotlib.pyplot.savefig(buf, format="png")',
			'\tbuf.seek(0)',
			'\timg_str = base64.b64encode(buf.read()).decode("utf-8")',
			'\tmatplotlib.pyplot.clf()',
			'\tbuf.close()',
			'\tprint(f"data:image/png;base64,{img_str}")',
			'matplotlib.pyplot.show = show'
		].join('\n'));
	}

	async function execute(id, code, files) {
		stdout = null;
		stderr = null;
		let result = null;
		if (files && files.length > 0) upload(files);
		try {
			if (code.includes('matplotlib')) await patchMatplotlib();
			result = clean(await pyodide.runPythonAsync(code));
		} catch (error) {
			stderr = error && error.message ? error.message : String(error);
		}
		post({ id: id, result: result, stdout: stdout, stderr: stderr });
	}

	window.addEventListener('message', async function (event) {
		if (event.source !== parent) return;
		const data = event.data || {};
		const id = data.id;
		try {
			if (!data.type || data.type === 'execute') {
				await ensureRuntime(data.packages || []);
				await execute(id, data.code, data.files);
				return;
			}
			await ensureRuntime();
			switch (data.type) {
				case 'fs:upload':
					upload(data.files, data.dir);
					post({ id: id, type: data.type, success: true });
					break;
				case 'fs:list':
					post({ id: id, type: data.type, entries: list(data.path) });
					break;
				case 'fs:read':
					try {
						const buffer = pyodide.FS.readFile(data.path).buffer;
						post({ id: id, type: data.type, data: buffer }, [buffer]);
					} catch (error) {
						post({ id: id, type: data.type, error: error && error.message ? error.message : String(error) });
					}
					break;
				case 'fs:delete':
					remove(data.path);
					post({ id: id, type: data.type, success: true });
					break;
				case 'fs:mkdir':
					pyodide.FS.mkdirTree(data.path);
					post({ id: id, type: data.type, success: true });
					break;
				case 'fs:sync':
					post({ id: id, type: data.type, success: true });
					break;
			}
		} catch (error) {
			post({ id: id, stderr: error && error.message ? error.message : String(error) });
		}
	});
})();
`;

// indexURL must be absolute because about:srcdoc can't be a base URL
const pyodideIndexURL = `${globalThis.location?.origin ?? ''}/pyodide/`;

const sandboxHtml = `<!doctype html><html><head><meta charset="utf-8"><script>window.__PYODIDE_INDEX_URL__=${JSON.stringify(pyodideIndexURL)}</script></head><body><script src="${pyodideIndexURL}pyodide.js"></script><script>${sandboxScript}</script></body></html>`;

export class PyodideSandboxHost {
	onmessage: MessageListener | null = null;
	onerror: ErrorListener | null = null;

	private iframe: HTMLIFrameElement;
	private ready = false;
	private queue: QueuedMessage[] = [];
	private messageListeners = new Set<MessageListener>();
	private errorListeners = new Set<ErrorListener>();
	private onWindowMessage: (event: MessageEvent) => void;
	private onIframeLoad: () => void;
	private onIframeError: (event: Event) => void;

	constructor() {
		this.iframe = document.createElement('iframe');
		this.iframe.setAttribute('sandbox', 'allow-scripts');
		this.iframe.setAttribute('aria-hidden', 'true');
		this.iframe.setAttribute('title', 'pyodide-sandbox');
		this.iframe.style.display = 'none';
		this.iframe.srcdoc = sandboxHtml;

		this.onWindowMessage = (event: MessageEvent) => {
			if (event.source !== this.iframe.contentWindow) {
				return;
			}

			const messageEvent = { data: event.data } as MessageEvent;
			this.onmessage?.(messageEvent);
			for (const listener of this.messageListeners) {
				listener(messageEvent);
			}
		};

		this.onIframeLoad = () => {
			this.ready = true;
			for (const item of this.queue) {
				this.post(item.message, item.transfer);
			}
			this.queue = [];
		};

		this.onIframeError = (event: Event) => {
			this.onerror?.(event);
			for (const listener of this.errorListeners) {
				listener(event);
			}
		};

		window.addEventListener('message', this.onWindowMessage);
		this.iframe.addEventListener('load', this.onIframeLoad, { once: true });
		this.iframe.addEventListener('error', this.onIframeError);
		document.body.appendChild(this.iframe);
	}

	postMessage(message: unknown, transfer: Transferable[] = []) {
		if (this.ready) {
			this.post(message, transfer);
		} else {
			this.queue.push({ message, transfer });
		}
	}

	addEventListener(type: 'message' | 'error', listener: MessageListener | ErrorListener) {
		if (type === 'message') {
			this.messageListeners.add(listener as MessageListener);
		} else if (type === 'error') {
			this.errorListeners.add(listener as ErrorListener);
		}
	}

	removeEventListener(type: 'message' | 'error', listener: MessageListener | ErrorListener) {
		if (type === 'message') {
			this.messageListeners.delete(listener as MessageListener);
		} else if (type === 'error') {
			this.errorListeners.delete(listener as ErrorListener);
		}
	}

	terminate() {
		window.removeEventListener('message', this.onWindowMessage);
		this.iframe.removeEventListener('load', this.onIframeLoad);
		this.iframe.removeEventListener('error', this.onIframeError);
		this.messageListeners.clear();
		this.errorListeners.clear();
		this.onmessage = null;
		this.onerror = null;
		this.iframe.remove();
	}

	private post(message: unknown, transfer: Transferable[]) {
		this.iframe.contentWindow?.postMessage(message, '*', transfer);
	}
}
