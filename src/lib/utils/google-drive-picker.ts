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
// Google Drive Picker API configuration
let API_KEY = '';
let CLIENT_ID = '';

// Function to fetch credentials from backend config
async function getCredentials() {
	const response = await fetch('/api/config');
	if (!response.ok) {
		throw new Error('Failed to fetch Google Drive credentials');
	}
	const config = await response.json();
	API_KEY = config.google_drive?.api_key;
	CLIENT_ID = config.google_drive?.client_id;

	if (!API_KEY || !CLIENT_ID) {
		throw new Error('Google Drive API credentials not configured');
	}
}
const SCOPE = [
	'https://www.googleapis.com/auth/drive.readonly',
	'https://www.googleapis.com/auth/drive.file'
];

// Validate required credentials
const validateCredentials = () => {
	if (!API_KEY || !CLIENT_ID) {
		throw new Error('Google Drive API credentials not configured');
	}
	if (API_KEY === '' || CLIENT_ID === '') {
		throw new Error('Please configure valid Google Drive API credentials');
	}
};

let pickerApiLoaded = false;
let oauthToken: string | null = null;
let initialized = false;

export const loadGoogleDriveApi = () => {
	return new Promise((resolve, reject) => {
		if (typeof gapi === 'undefined') {
			const script = document.createElement('script');
			script.src = 'https://apis.google.com/js/api.js';
			script.onload = () => {
				gapi.load('picker', () => {
					pickerApiLoaded = true;
					resolve(true);
				});
			};
			script.onerror = reject;
			document.body.appendChild(script);
		} else {
			gapi.load('picker', () => {
				pickerApiLoaded = true;
				resolve(true);
			});
		}
	});
};

export const loadGoogleAuthApi = () => {
	return new Promise((resolve, reject) => {
		if (typeof google === 'undefined') {
			const script = document.createElement('script');
			script.src = 'https://accounts.google.com/gsi/client';
			script.onload = resolve;
			script.onerror = reject;
			document.body.appendChild(script);
		} else {
			resolve(true);
		}
	});
};

export const getAuthToken = async () => {
	if (!oauthToken) {
		return new Promise((resolve, reject) => {
			const tokenClient = google.accounts.oauth2.initTokenClient({
				client_id: CLIENT_ID,
				scope: SCOPE.join(' '),
				callback: (response: any) => {
					if (response.access_token) {
						oauthToken = response.access_token;
						resolve(oauthToken);
					} else {
						reject(new Error('Failed to get access token'));
					}
				},
				error_callback: (error: any) => {
					reject(new Error(error.message || 'OAuth error occurred'));
				}
			});
			tokenClient.requestAccessToken();
		});
	}
	void gr_check(oauthToken, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return oauthToken;
};

const initialize = async () => {
	if (!initialized) {
		await getCredentials();
		validateCredentials();
		await Promise.all([loadGoogleDriveApi(), loadGoogleAuthApi()]);
		initialized = true;
	}
};

export const createPicker = () => {
	return new Promise(async (resolve, reject) => {
		try {
			console.log('Initializing Google Drive Picker...');
			await initialize();
			console.log('Getting auth token...');
			const token = await getAuthToken();
			if (!token) {
				console.error('Failed to get OAuth token');
				throw new Error('Unable to get OAuth token');
			}
			console.log('Auth token obtained successfully');

			const picker = new google.picker.PickerBuilder()
				.enableFeature(google.picker.Feature.NAV_HIDDEN)
				.enableFeature(google.picker.Feature.MULTISELECT_ENABLED)
				.addView(
					new google.picker.DocsView()
						.setIncludeFolders(false)
						.setSelectFolderEnabled(false)
						.setMimeTypes(
							'application/pdf,text/plain,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.google-apps.document,application/vnd.google-apps.spreadsheet,application/vnd.google-apps.presentation'
						)
				)
				.setOAuthToken(token)
				.setDeveloperKey(API_KEY)
				// Remove app ID setting as it's not needed and can cause 404 errors
				.setCallback(async (data: any) => {
					if (data[google.picker.Response.ACTION] === google.picker.Action.PICKED) {
						try {
							const doc = data[google.picker.Response.DOCUMENTS][0];
							const fileId = doc[google.picker.Document.ID];
							const fileName = doc[google.picker.Document.NAME];
							const fileUrl = doc[google.picker.Document.URL];

							if (!fileId || !fileName) {
								throw new Error('Required file details missing');
							}

							// Construct download URL based on MIME type
							const mimeType = doc[google.picker.Document.MIME_TYPE];

							let downloadUrl;
							let exportFormat;

							if (mimeType.includes('google-apps')) {
								// Handle Google Workspace files
								if (mimeType.includes('document')) {
									exportFormat = 'text/plain';
								} else if (mimeType.includes('spreadsheet')) {
									exportFormat = 'text/csv';
								} else if (mimeType.includes('presentation')) {
									exportFormat = 'text/plain';
								} else {
									exportFormat = 'application/pdf';
								}
								downloadUrl = `https://www.googleapis.com/drive/v3/files/${fileId}/export?mimeType=${encodeURIComponent(exportFormat)}`;
							} else {
								// Regular files use direct download URL
								downloadUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`;
							}
							// Create a Blob from the file download
							const response = await fetch(downloadUrl, {
								headers: {
									Authorization: `Bearer ${token}`,
									Accept: '*/*'
								}
							});

							if (!response.ok) {
								const errorText = await response.text();
								console.error('Download failed:', {
									status: response.status,
									statusText: response.statusText,
									error: errorText
								});
								throw new Error(`Failed to download file (${response.status}): ${errorText}`);
							}

							const blob = await response.blob();
							const result = {
								id: fileId,
								name: fileName,
								url: downloadUrl,
								blob: blob,
								headers: {
									Authorization: `Bearer ${token}`,
									Accept: '*/*'
								}
							};
							resolve(result);
						} catch (error) {
							reject(error);
						}
					} else if (data[google.picker.Response.ACTION] === google.picker.Action.CANCEL) {
						resolve(null);
					}
				})
				.build();
			picker.setVisible(true);
		} catch (error) {
			void gr_check(error, "agent", "log", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_014", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_033", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_006", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
			  if (_grExc instanceof GRBlockedError) {
			    console.error("Lineaje: BLOCK at 'agent->log' could not be enforced — call site is synchronous (fire-and-forget)");
			  }
			}); // fire-and-forget (sync context)
			console.error('Google Drive Picker error:', error);
			reject(error);
		}
	});
};
