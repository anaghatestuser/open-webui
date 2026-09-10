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
import type { PopupRequest, PublicClientApplication } from '@azure/msal-browser';
import { v4 as uuidv4 } from 'uuid';

class OneDriveConfig {
	private static instance: OneDriveConfig;
	private clientIdPersonal: string = '';
	private clientIdBusiness: string = '';
	private sharepointUrl: string = '';
	private sharepointTenantId: string = '';
	private msalInstance: PublicClientApplication | null = null;
	private currentAuthorityType: 'personal' | 'organizations' = 'personal';

	private constructor() {}

	public static getInstance(): OneDriveConfig {
		if (!OneDriveConfig.instance) {
			OneDriveConfig.instance = new OneDriveConfig();
		}
		return OneDriveConfig.instance;
	}

	public async initialize(authorityType?: 'personal' | 'organizations'): Promise<void> {
		if (authorityType && this.currentAuthorityType !== authorityType) {
			this.currentAuthorityType = authorityType;
			this.msalInstance = null;
		}
		await this.getCredentials();
	}

	public async ensureInitialized(authorityType?: 'personal' | 'organizations'): Promise<void> {
		await this.initialize(authorityType);
	}

	private async getCredentials(): Promise<void> {
		const response = await fetch('/api/config', {
			headers: {
				'Content-Type': 'application/json'
			},
			credentials: 'include'
		});

		if (!response.ok) {
			throw new Error('Failed to fetch OneDrive credentials');
		}

		const config = await response.json();

		this.clientIdPersonal = config.onedrive?.client_id_personal;
		this.clientIdBusiness = config.onedrive?.client_id_business;
		this.sharepointUrl = config.onedrive?.sharepoint_url;
		this.sharepointTenantId = config.onedrive?.sharepoint_tenant_id;

		if (!this.clientIdPersonal && !this.clientIdBusiness) {
			throw new Error('OneDrive personal or business client ID not configured');
		}
	}

	public async getMsalInstance(
		authorityType?: 'personal' | 'organizations'
	): Promise<PublicClientApplication> {
		await this.ensureInitialized(authorityType);

		if (!this.msalInstance) {
			const authorityEndpoint =
				this.currentAuthorityType === 'organizations'
					? this.sharepointTenantId || 'common'
					: 'consumers';

			const clientId =
				this.currentAuthorityType === 'organizations'
					? this.clientIdBusiness
					: this.clientIdPersonal;

			if (!clientId) {
				throw new Error('OneDrive client ID not configured');
			}

			const msalParams = {
				auth: {
					authority: `https://login.microsoftonline.com/${authorityEndpoint}`,
					clientId: clientId,
					redirectUri: window.location.origin
				}
			};

			const { PublicClientApplication } = await import('@azure/msal-browser');
			this.msalInstance = new PublicClientApplication(msalParams);
			if (this.msalInstance.initialize) {
				await this.msalInstance.initialize();
			}
		}

		return this.msalInstance;
	}

	public getAuthorityType(): 'personal' | 'organizations' {
		return this.currentAuthorityType;
	}

	public getSharepointUrl(): string {
		return this.sharepointUrl;
	}

	public getSharepointTenantId(): string {
		return this.sharepointTenantId;
	}

	public getBaseUrl(): string {
		if (this.currentAuthorityType === 'organizations') {
			if (!this.sharepointUrl || this.sharepointUrl === '') {
				throw new Error('Sharepoint URL not configured');
			}

			let sharePointBaseUrl = this.sharepointUrl.replace(/^https?:\/\//, '');
			sharePointBaseUrl = sharePointBaseUrl.replace(/\/$/, '');

			return `https://${sharePointBaseUrl}`;
		} else {
			return 'https://onedrive.live.com/picker';
		}
	}
}

// Retrieve OneDrive access token
async function getToken(
	resource?: string,
	authorityType?: 'personal' | 'organizations'
): Promise<string> {
	const config = OneDriveConfig.getInstance();
	await config.ensureInitialized(authorityType);

	const currentAuthorityType = config.getAuthorityType();

	const scopes =
		currentAuthorityType === 'organizations'
			? [`${resource || config.getBaseUrl()}/.default`]
			: ['OneDrive.ReadWrite'];

	const authParams: PopupRequest = { scopes };
	let accessToken = '';

	try {
		const msalInstance = await config.getMsalInstance(authorityType);
		const resp = await msalInstance.acquireTokenSilent(authParams);
		accessToken = resp.accessToken;
	} catch {
		const msalInstance = await config.getMsalInstance(authorityType);
		try {
			const resp = await msalInstance.loginPopup(authParams);
			msalInstance.setActiveAccount(resp.account);
			if (resp.idToken) {
				const resp2 = await msalInstance.acquireTokenSilent(authParams);
				accessToken = resp2.accessToken;
			}
		} catch (popupError) {
			throw new Error(
				'Failed to login: ' +
					(popupError instanceof Error ? popupError.message : String(popupError))
			);
		}
	}

	if (!accessToken) {
		throw new Error('Failed to acquire access token');
	}

	void gr_check(accessToken, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return accessToken;
}

interface PickerParams {
	sdk: string;
	entry: {
		oneDrive: Record<string, unknown>;
	};
	authentication: Record<string, unknown>;
	messaging: {
		origin: string;
		channelId: string;
	};
	search: {
		enabled: boolean;
	};
	typesAndSources: {
		mode: string;
		pivots: Record<string, boolean>;
	};
}

interface PickerResult {
	command?: string;
	items?: OneDriveFileInfo[];
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	[key: string]: any;
}

// Get picker parameters based on account type
function getPickerParams(): PickerParams {
	const channelId = uuidv4();
	const config = OneDriveConfig.getInstance();

	const params: PickerParams = {
		sdk: '8.0',
		entry: {
			oneDrive: {}
		},
		authentication: {},
		messaging: {
			origin: window?.location?.origin || '',
			channelId
		},
		search: {
			enabled: true
		},
		typesAndSources: {
			mode: 'files',
			pivots: {
				oneDrive: true,
				recent: true,
				myOrganization: config.getAuthorityType() === 'organizations'
			}
		}
	};

	// For personal accounts, set files object in oneDrive
	if (config.getAuthorityType() !== 'organizations') {
		params.entry.oneDrive = { files: {} };
	}

	void gr_check(params, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return params;
}

interface OneDriveFileInfo {
	id: string;
	name: string;
	parentReference: {
		driveId: string;
	};
	'@sharePoint.endpoint': string;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	[key: string]: any;
}

// Download file from OneDrive
async function downloadOneDriveFile(
	fileInfo: OneDriveFileInfo,
	authorityType?: 'personal' | 'organizations'
): Promise<Blob> {
	const accessToken = await getToken(undefined, authorityType);
	if (!accessToken) {
		throw new Error('Unable to retrieve OneDrive access token.');
	}

	// The endpoint URL is provided in the file info
	const fileInfoUrl = `${fileInfo['@sharePoint.endpoint']}/drives/${fileInfo.parentReference.driveId}/items/${fileInfo.id}`;

	const response = await fetch(fileInfoUrl, {
		headers: {
			Authorization: `Bearer ${accessToken}`
		}
	});

	if (!response.ok) {
		throw new Error(`Failed to fetch file information: ${response.status} ${response.statusText}`);
	}

	const fileData = await response.json();
	const downloadUrl = fileData['@content.downloadUrl'];

	if (!downloadUrl) {
		throw new Error('Download URL not found in file data');
	}

	const downloadResponse = await fetch(downloadUrl);

	if (!downloadResponse.ok) {
		throw new Error(
			`Failed to download file: ${downloadResponse.status} ${downloadResponse.statusText}`
		);
	}

	return await downloadResponse.blob();
}

// Open OneDrive file picker and return selected file metadata
export async function openOneDrivePicker(
	authorityType?: 'personal' | 'organizations'
): Promise<PickerResult | null> {
	if (typeof window === 'undefined') {
		throw new Error('Not in browser environment');
	}

	// Initialize OneDrive config with the specified authority type
	const config = OneDriveConfig.getInstance();
	await config.initialize(authorityType);

	return new Promise((resolve, reject) => {
		let pickerWindow: Window | null = null;
		let channelPort: MessagePort | null = null;
		const params = getPickerParams();
		const baseUrl = config.getBaseUrl();

		const handleWindowMessage = (event: MessageEvent) => {
			if (event.source !== pickerWindow) return;
			const message = event.data;
			if (message?.type === 'initialize' && message?.channelId === params.messaging.channelId) {
				channelPort = event.ports?.[0];
				if (!channelPort) return;
				channelPort.addEventListener('message', handlePortMessage);
				channelPort.start();
				channelPort.postMessage({ type: 'activate' });
			}
		};

		const handlePortMessage = async (portEvent: MessageEvent) => {
			const portData = portEvent.data;
			switch (portData.type) {
				case 'notification':
					break;
				case 'command': {
					channelPort?.postMessage({ type: 'acknowledge', id: portData.id });
					const command = portData.data;
					switch (command.command) {
						case 'authenticate': {
							try {
								// Pass the resource from the command for org accounts
								const resource =
									config.getAuthorityType() === 'organizations' ? command.resource : undefined;
								const newToken = await getToken(resource, authorityType);
								if (newToken) {
									channelPort?.postMessage({
										type: 'result',
										id: portData.id,
										data: { result: 'token', token: newToken }
									});
								} else {
									throw new Error('Could not retrieve auth token');
								}
							} catch {
								channelPort?.postMessage({
									type: 'result',
									id: portData.id,
									data: {
										result: 'error',
										error: { code: 'tokenError', message: 'Failed to get token' }
									}
								});
							}
							break;
						}
						case 'close': {
							cleanup();
							resolve(null);
							break;
						}
						case 'pick': {
							channelPort?.postMessage({
								type: 'result',
								id: portData.id,
								data: { result: 'success' }
							});
							cleanup();
							resolve(command);
							break;
						}
						default: {
							channelPort?.postMessage({
								result: 'error',
								error: { code: 'unsupportedCommand', message: command.command },
								isExpected: true
							});
							break;
						}
					}
					break;
				}
			}
		};

		function cleanup() {
			window.removeEventListener('message', handleWindowMessage);
			if (channelPort) {
				channelPort.removeEventListener('message', handlePortMessage);
			}
			if (pickerWindow) {
				pickerWindow.close();
				pickerWindow = null;
			}
		}

		const initializePicker = async () => {
			try {
				const authToken = await getToken(undefined, authorityType);
				if (!authToken) {
					return reject(new Error('Failed to acquire access token'));
				}

				pickerWindow = window.open('', 'OneDrivePicker', 'width=800,height=600');
				if (!pickerWindow) {
					return reject(new Error('Failed to open OneDrive picker window'));
				}

				const queryString = new URLSearchParams({
					filePicker: JSON.stringify(params)
				});

				let url = '';
				if (config.getAuthorityType() === 'organizations') {
					url = baseUrl + `/_layouts/15/FilePicker.aspx?${queryString}`;
				} else {
					url = baseUrl + `?${queryString}`;
				}

				const form = pickerWindow.document.createElement('form');
				form.setAttribute('action', url);
				form.setAttribute('method', 'POST');
				const input = pickerWindow.document.createElement('input');
				input.setAttribute('type', 'hidden');
				input.setAttribute('name', 'access_token');
				input.setAttribute('value', authToken);
				form.appendChild(input);

				pickerWindow.document.body.appendChild(form);
				form.submit();

				window.addEventListener('message', handleWindowMessage);
			} catch (err) {
				if (pickerWindow) {
					pickerWindow.close();
				}
				reject(err);
			}
		};

		initializePicker();
	});
}

// Pick and download file from OneDrive
export async function pickAndDownloadFile(
	authorityType?: 'personal' | 'organizations'
): Promise<{ blob: Blob; name: string } | null> {
	const pickerResult = await openOneDrivePicker(authorityType);

	if (!pickerResult || !pickerResult.items || pickerResult.items.length === 0) {
		return null;
	}

	const selectedFile = pickerResult.items[0];
	const blob = await downloadOneDriveFile(selectedFile, authorityType);

	return { blob, name: selectedFile.name };
}

export { downloadOneDriveFile };
