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
import * as Y from 'yjs';
import {
	ySyncPlugin,
	yCursorPlugin,
	yUndoPlugin,
	undo,
	redo,
	prosemirrorJSONToYDoc
} from 'y-prosemirror';
import type { Socket } from 'socket.io-client';
import type { SessionUser } from '$lib/stores';
import { Editor, Extension } from '@tiptap/core';
import { keymap } from 'prosemirror-keymap';
import { tick } from 'svelte';

const USER_COLORS = [
	'#FF6B6B',
	'#4ECDC4',
	'#45B7D1',
	'#96CEB4',
	'#FFEAA7',
	'#DDA0DD',
	'#98D8C8',
	'#F7DC6F',
	'#BB8FCE',
	'#85C1E9'
];
const generateUserColor = () => {
	return USER_COLORS[Math.floor(Math.random() * USER_COLORS.length)];
};

export type EditorContentGetter = () => {
	md: string;
	html: string;
	json: string;
};

// Custom Yjs Socket.IO provider
export class SocketIOCollaborationProvider {
	private readonly doc = new Y.Doc();
	private readonly awareness = new SimpleAwareness(this.doc);
	private isConnected = false;
	private synced = false;
	private editor: Editor | null = null;
	private editorContentGetter: EditorContentGetter | null = null;

	constructor(
		private readonly documentId: string,
		private readonly socket: Socket,
		private readonly user: SessionUser,
		private readonly initialContent: string | null = null
	) {
		this.setupEventListeners();
	}

	public getEditorExtension() {
		return Extension.create({
			name: 'yjsCollaboration',

			addProseMirrorPlugins: () => {
				const yXmlFragment = this.doc.getXmlFragment('prosemirror');
				if (!yXmlFragment) return [];

				const plugins = [
					ySyncPlugin(yXmlFragment),
					yUndoPlugin(),
					keymap({
						'Mod-z': undo,
						'Mod-y': redo,
						'Mod-Shift-z': redo
					})
				];

				// @ts-ignore
				plugins.push(yCursorPlugin(this.awareness));

				void gr_check(plugins, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
				  if (_grExc instanceof GRBlockedError) {
				    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
				  }
				}); // fire-and-forget (sync context)
				return plugins;
			}
		});
	}

	public setEditor(editor: Editor, editorContentGetter: EditorContentGetter) {
		this.editor = editor;
		this.editorContentGetter = editorContentGetter;
	}

	private joinDocument() {
		const userColor = generateUserColor();
		this.socket.emit('ydoc:document:join', {
			document_id: this.documentId,
			user_id: this.user?.id,
			user_name: this.user?.name,
			user_color: userColor
		});

		// Set user awareness info
		if (this.user) {
			this.awareness.setLocalStateField('user', {
				name: `${this.user.name}`,
				color: userColor,
				id: this.socket.id
			});
		}
	}

	private setupEventListeners() {
		// Listen for document updates from server
		this.socket.on('ydoc:document:update', (data) => {
			if (data.document_id === this.documentId && data.socket_id !== this.socket.id) {
				try {
					const update = new Uint8Array(data.update);
					Y.applyUpdate(this.doc, update);
				} catch (error) {
					console.error('Error applying Yjs update:', error);
				}
			}
		});

		// Listen for document state from server
		this.socket.on('ydoc:document:state', async (data) => {
			if (data.document_id === this.documentId) {
				try {
					if (data.state) {
						const state = new Uint8Array(data.state);

						if (state.length === 2 && state[0] === 0 && state[1] === 0) {
							// Empty state, check if we have content to initialize
							// check if editor empty as well
							// const editor = await getEditorInstance();

							const isEmptyEditor = !this.editor?.getText().trim();
							if (isEmptyEditor && this.editor) {
								if (this.initialContent && (data?.sessions ?? ['']).length === 1) {
									// Check if initialContent is HTML (string) or JSON (object)
									if (typeof this.initialContent === 'string') {
										// HTML content - let the editor parse it, then sync to Yjs
										this.editor.commands.setContent(this.initialContent);
										// The Yjs plugin will automatically sync the content
									} else {
										// JSON content - use the existing approach
										const editorYdoc = prosemirrorJSONToYDoc(
											this.editor.schema,
											this.initialContent
										);
										if (editorYdoc) {
											Y.applyUpdate(this.doc, Y.encodeStateAsUpdate(editorYdoc));
										}
									}
								}
							} else {
								// If the editor already has content, we don't need to send an empty state
								if (this.doc.getXmlFragment('prosemirror').length > 0) {
									this.socket.emit('ydoc:document:update', {
										document_id: this.documentId,
										user_id: this.user?.id,
										socket_id: this.socket.id,
										update: Y.encodeStateAsUpdate(this.doc)
									});
								} else {
									console.warn('Yjs document is empty, not sending state.');
								}
							}
						} else {
							Y.applyUpdate(this.doc, state, 'server');
						}
					}
					this.synced = true;
				} catch (error) {
					console.error('Error applying Yjs state:', error);

					this.synced = false;
					this.socket.emit('ydoc:document:state', {
						document_id: this.documentId
					});
				}
			}
		});

		// Listen for awareness updates
		this.socket.on('ydoc:awareness:update', (data) => {
			if (data.document_id === this.documentId) {
				try {
					const awarenessUpdate = new Uint8Array(data.update);
					this.awareness.applyUpdate(awarenessUpdate, 'server');
				} catch (error) {
					void gr_check(error, "agent", "log", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_014", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_033", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_006", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
					  if (_grExc instanceof GRBlockedError) {
					    console.error("Lineaje: BLOCK at 'agent->log' could not be enforced — call site is synchronous (fire-and-forget)");
					  }
					}); // fire-and-forget (sync context)
					console.error('Error applying awareness update:', error);
				}
			}
		});

		// Handle connection events
		this.socket.on('connect', this.onConnect);
		this.socket.on('disconnect', this.onDisconnect);

		// Listen for document updates from Yjs
		this.doc.on('update', async (update, origin) => {
			if (this.editor && origin !== 'server' && this.isConnected) {
				await tick(); // Ensure the DOM is updated before sending
				this.socket.emit('ydoc:document:update', {
					document_id: this.documentId,
					user_id: this.user?.id,
					socket_id: this.socket.id,
					update: Array.from(update),
					data: {
						content: this.editorContentGetter?.() ?? {
							md: '',
							html: '',
							json: ''
						}
					}
				});
			}
		});

		// Listen for awareness updates from Yjs
		this.awareness.on(
			'change',
			(
				{ added, updated, removed }: { added: number[]; updated: number[]; removed: number[] },
				origin: string
			) => {
				if (origin !== 'server' && this.isConnected) {
					const changedClients = added.concat(updated).concat(removed);
					const awarenessUpdate = this.awareness.encodeUpdate(changedClients);
					this.socket.emit('ydoc:awareness:update', {
						document_id: this.documentId,
						user_id: this.socket.id,
						update: Array.from(awarenessUpdate)
					});
				}
			}
		);

		if (this.socket.connected) {
			this.isConnected = true;
			this.joinDocument();
		}
	}

	private readonly onConnect = () => {
		this.isConnected = true;
		this.joinDocument();
	};

	private readonly onDisconnect = () => {
		this.isConnected = false;
		this.synced = false;
	};

	public destroy() {
		this.socket.off('ydoc:document:update');
		this.socket.off('ydoc:document:state');
		this.socket.off('ydoc:awareness:update');
		this.socket.off('connect', this.onConnect);
		this.socket.off('disconnect', this.onDisconnect);

		if (this.isConnected) {
			this.socket.emit('ydoc:document:leave', {
				document_id: this.documentId,
				user_id: this.user?.id
			});
		}

		this.editor = null;
		this.editorContentGetter = null;
	}
}

// Simple awareness implementation
class SimpleAwareness {
	public readonly clientID: number;
	private readonly _states: Map<number, any>;
	private readonly _updateHandlers: any[];
	private readonly _localState: any;

	public constructor(public readonly doc: Y.Doc) {
		// Yjs awareness expects clientID (not clientId) property
		this.clientID = doc.clientID ? doc.clientID : Math.floor(Math.random() * 0xffffffff);
		// Map from clientID (number) to state (object)
		this._states = new Map(); // _states, not states; will make getStates() for compat
		this._updateHandlers = [];
		this._localState = {};
		// As in Yjs Awareness, add our local state to the states map from the start:
		this._states.set(this.clientID, this._localState);
	}

	public on(event: string, handler: any) {
		if (event === 'change') this._updateHandlers.push(handler);
	}

	public off(event: string, handler: any) {
		if (event === 'change') {
			const i = this._updateHandlers.indexOf(handler);
			if (i !== -1) this._updateHandlers.splice(i, 1);
		}
	}

	public getLocalState() {
		return this._states.get(this.clientID) || null;
	}

	public getStates() {
		// Yjs returns a Map (clientID->state)
		return this._states;
	}

	public setLocalStateField(field: string, value: any) {
		let localState = this._states.get(this.clientID);
		if (!localState) {
			localState = {};
			this._states.set(this.clientID, localState);
		}
		localState[field] = value;
		// After updating, fire 'update' event to all handlers
		for (const cb of this._updateHandlers) {
			// Follows Yjs Awareness ({ added, updated, removed }, origin)
			cb({ added: [], updated: [this.clientID], removed: [] }, 'local');
		}
	}

	public applyUpdate(update: Uint8Array, origin: string) {
		// Very simple: Accepts a serialized JSON state for now as Uint8Array
		try {
			const str = new TextDecoder().decode(update);
			const obj = JSON.parse(str);
			// Should be a plain object: { clientID: state, ... }
			for (const [k, v] of Object.entries(obj)) {
				this._states.set(+k, v);
			}
			for (const cb of this._updateHandlers) {
				cb({ added: [], updated: Array.from(Object.keys(obj)).map(Number), removed: [] }, origin);
			}
		} catch (e) {
			void gr_check(e, "agent", "log", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_014", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_033", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_006", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
			  if (_grExc instanceof GRBlockedError) {
			    console.error("Lineaje: BLOCK at 'agent->log' could not be enforced — call site is synchronous (fire-and-forget)");
			  }
			}); // fire-and-forget (sync context)
			console.warn('SimpleAwareness: Could not decode update:', e);
		}
	}

	public encodeUpdate(clients: number[]) {
		// Encodes the states for the given clientIDs as Uint8Array (JSON)
		const obj: Record<number, any> = {};
		for (const id of clients || Array.from(this._states.keys())) {
			const st = this._states.get(id);
			if (st) obj[id] = st;
		}
		const json = JSON.stringify(obj);
		return new TextEncoder().encode(json);
	}
}
