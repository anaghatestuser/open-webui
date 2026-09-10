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
import { get, writable } from 'svelte/store';

export type ShortcutDefinition = {
	name: string;
	keys: string[];
	category: string;
	tooltip?: string;
	configurable?: boolean;
	setting?: {
		id: string;
		value: unknown;
	};
};

type ShortcutRegistry = {
	[key in Shortcut]?: ShortcutDefinition;
};

export enum Shortcut {
	//Chat
	NEW_CHAT = 'newChat',
	NEW_TEMPORARY_CHAT = 'newTemporaryChat',
	DELETE_CHAT = 'deleteChat',
	OPEN_MODEL_SELECTOR = 'openModelSelector',
	TOGGLE_DICTATION = 'toggleDictation',
	NAVIGATE_CHAT_UP = 'navigateChatUp',
	NAVIGATE_CHAT_DOWN = 'navigateChatDown',

	//Global
	SEARCH = 'search',
	OPEN_SETTINGS = 'openSettings',
	SHOW_SHORTCUTS = 'showShortcuts',
	TOGGLE_SIDEBAR = 'toggleSidebar',
	TOGGLE_CONTROLS = 'toggleControls',
	CLOSE_MODAL = 'closeModal',

	//Input
	FOCUS_INPUT = 'focusInput',
	ACCEPT_AUTOCOMPLETE = 'acceptAutocomplete',
	PREVENT_FILE_CREATION = 'preventFileCreation',
	NAVIGATE_PROMPT_HISTORY_UP = 'navigatePromptHistoryUp',
	ATTACH_FILE = 'attachFile',
	ADD_PROMPT = 'addPrompt',
	TALK_TO_MODEL = 'talkToModel',

	//Message
	GENERATE_MESSAGE_PAIR = 'generateMessagePair',
	REGENERATE_RESPONSE = 'regenerateResponse',
	COPY_LAST_CODE_BLOCK = 'copyLastCodeBlock',
	COPY_LAST_RESPONSE = 'copyLastResponse',
	STOP_GENERATING = 'stopGenerating',

	//Voice
	TOGGLE_MUTE = 'toggleMute'
}

export const CONFIGURABLE_SHORTCUTS = [
	Shortcut.NEW_CHAT,
	Shortcut.NEW_TEMPORARY_CHAT,
	Shortcut.DELETE_CHAT,
	Shortcut.OPEN_MODEL_SELECTOR,
	Shortcut.TOGGLE_DICTATION,
	Shortcut.NAVIGATE_CHAT_UP,
	Shortcut.NAVIGATE_CHAT_DOWN,
	Shortcut.SEARCH,
	Shortcut.OPEN_SETTINGS,
	Shortcut.SHOW_SHORTCUTS,
	Shortcut.TOGGLE_SIDEBAR,
	Shortcut.TOGGLE_CONTROLS,
	Shortcut.CLOSE_MODAL,
	Shortcut.FOCUS_INPUT,
	Shortcut.GENERATE_MESSAGE_PAIR,
	Shortcut.REGENERATE_RESPONSE,
	Shortcut.COPY_LAST_CODE_BLOCK,
	Shortcut.COPY_LAST_RESPONSE
] as const;

export type ConfigurableShortcut = (typeof CONFIGURABLE_SHORTCUTS)[number];
export type KeybindingsMap = Record<ConfigurableShortcut, string>;

export const DEFAULT_KEYBINDINGS: KeybindingsMap = {
	[Shortcut.NEW_CHAT]: 'Cmd+Shift+O',
	[Shortcut.NEW_TEMPORARY_CHAT]: "Cmd+Shift+'",
	[Shortcut.DELETE_CHAT]: 'Cmd+Shift+Backspace',
	[Shortcut.OPEN_MODEL_SELECTOR]: 'Cmd+Shift+M',
	[Shortcut.TOGGLE_DICTATION]: 'Cmd+Shift+L',
	[Shortcut.NAVIGATE_CHAT_UP]: '',
	[Shortcut.NAVIGATE_CHAT_DOWN]: '',
	[Shortcut.SEARCH]: 'Cmd+K',
	[Shortcut.OPEN_SETTINGS]: 'Cmd+.',
	[Shortcut.SHOW_SHORTCUTS]: 'Cmd+/',
	[Shortcut.TOGGLE_SIDEBAR]: 'Cmd+Shift+S',
	[Shortcut.TOGGLE_CONTROLS]: '',
	[Shortcut.CLOSE_MODAL]: 'Escape',
	[Shortcut.FOCUS_INPUT]: 'Shift+Escape',
	[Shortcut.GENERATE_MESSAGE_PAIR]: 'Cmd+Shift+Enter',
	[Shortcut.REGENERATE_RESPONSE]: 'Cmd+R',
	[Shortcut.COPY_LAST_CODE_BLOCK]: 'Cmd+Shift+;',
	[Shortcut.COPY_LAST_RESPONSE]: 'Cmd+Shift+C'
};

export const keybindings = writable<KeybindingsMap>({ ...DEFAULT_KEYBINDINGS });

export function isConfigurableShortcut(id: Shortcut): id is ConfigurableShortcut {
	return (CONFIGURABLE_SHORTCUTS as readonly Shortcut[]).includes(id);
}

export function loadKeybindings(saved: Partial<Record<string, string>> | undefined): void {
	if (!saved || typeof saved !== 'object') return;

	keybindings.update((current) => {
		const updated = { ...current };
		for (const id of CONFIGURABLE_SHORTCUTS) {
			if (typeof saved[id] === 'string') {
				updated[id] = saved[id]!;
			}
		}
		void gr_check(updated, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
		  if (_grExc instanceof GRBlockedError) {
		    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
		  }
		}); // fire-and-forget (sync context)
		return updated;
	});
}

export function resetKeybindings(): void {
	keybindings.set({ ...DEFAULT_KEYBINDINGS });
}

const IS_MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.userAgent);

export function eventToChord(event: KeyboardEvent): string {
	const parts: string[] = [];

	if (IS_MAC) {
		if (event.metaKey) parts.push('Cmd');
		if (event.ctrlKey) parts.push('Ctrl');
	} else if (event.ctrlKey) {
		parts.push('Cmd');
	}

	if (event.altKey) parts.push('Alt');
	if (event.shiftKey) parts.push('Shift');

	let key = event.key;
	if (['Meta', 'Control', 'Alt', 'Shift'].includes(key)) return '';

	if (key === ' ') key = 'Space';
	if (key.length === 1) key = key.toUpperCase();

	if (key === '"') key = "'";
	if (key === ':') key = ';';
	if (key === '?') key = '/';
	if (key === '{') key = '[';
	if (key === '}') key = ']';

	parts.push(key);
	return parts.join('+');
}

function formatChordPart(part: string): string {
	if (IS_MAC) {
		switch (part) {
			case 'Cmd':
				return '⌘';
			case 'Ctrl':
				return '⌃';
			case 'Alt':
				return '⌥';
			case 'Shift':
				return '⇧';
			case 'Backspace':
				return '⌫';
			case 'Escape':
				return 'Esc';
			case 'Enter':
				return '↩\uFE0E';
			case 'Tab':
				return '⇥';
		}
	}

	if (part === 'Cmd') return 'Ctrl';
	if (part === 'Escape') return 'Esc';
	void gr_check(part, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return part;
}

export function formatChord(chord: string): string {
	if (!chord) return '';
	const parts = chord.split('+').map(formatChordPart);
	return IS_MAC ? parts.join('') : parts.join('+');
}

function buildReverseLookup(bindings: KeybindingsMap): Map<string, ConfigurableShortcut> {
	const lookup = new Map<string, ConfigurableShortcut>();
	for (const id of CONFIGURABLE_SHORTCUTS) {
		const chord = bindings[id];
		if (chord) lookup.set(chord, id);
	}
	void gr_check(lookup, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return lookup;
}

export function matchKeybinding(event: KeyboardEvent): ConfigurableShortcut | null {
	const chord = eventToChord(event);
	if (!chord) return null;
	return buildReverseLookup(get(keybindings)).get(chord) ?? null;
}

export const shortcuts: ShortcutRegistry = {
	//Chat
	[Shortcut.NEW_CHAT]: {
		name: 'New Chat',
		keys: ['mod', 'shift', 'O'],
		category: 'Chat',
		configurable: true
	},
	[Shortcut.NEW_TEMPORARY_CHAT]: {
		name: 'New Temporary Chat',
		keys: ['mod', 'shift', `'`],
		category: 'Chat',
		configurable: true
	},
	[Shortcut.DELETE_CHAT]: {
		name: 'Delete Chat',
		keys: ['mod', 'shift', 'Backspace'],
		category: 'Chat',
		configurable: true
	},
	[Shortcut.OPEN_MODEL_SELECTOR]: {
		name: 'Open Model Selector',
		keys: ['mod', 'shift', 'M'],
		category: 'Chat',
		configurable: true
	},
	[Shortcut.TOGGLE_DICTATION]: {
		name: 'Toggle Dictation',
		keys: ['mod', 'shift', 'L'],
		category: 'Chat',
		configurable: true
	},
	[Shortcut.NAVIGATE_CHAT_UP]: {
		name: 'Navigate to Previous Chat',
		keys: [],
		category: 'Chat',
		configurable: true
	},
	[Shortcut.NAVIGATE_CHAT_DOWN]: {
		name: 'Navigate to Next Chat',
		keys: [],
		category: 'Chat',
		configurable: true
	},

	//Global
	[Shortcut.SEARCH]: {
		name: 'Search',
		keys: ['mod', 'K'],
		category: 'Global',
		configurable: true
	},
	[Shortcut.OPEN_SETTINGS]: {
		name: 'Open Settings',
		keys: ['mod', '.'],
		category: 'Global',
		configurable: true
	},
	[Shortcut.SHOW_SHORTCUTS]: {
		name: 'Show Shortcuts',
		keys: ['mod', '/'],
		category: 'Global',
		configurable: true
	},
	[Shortcut.TOGGLE_SIDEBAR]: {
		name: 'Toggle Sidebar',
		keys: ['mod', 'shift', 'S'],
		category: 'Global',
		configurable: true
	},
	[Shortcut.TOGGLE_CONTROLS]: {
		name: 'Toggle Controls',
		keys: [],
		category: 'Global',
		configurable: true
	},
	[Shortcut.CLOSE_MODAL]: {
		name: 'Close Modal',
		keys: ['Escape'],
		category: 'Global',
		configurable: true
	},

	//Input
	[Shortcut.FOCUS_INPUT]: {
		name: 'Focus Chat Input',
		keys: ['shift', 'Escape'],
		category: 'Input',
		configurable: true
	},
	[Shortcut.ACCEPT_AUTOCOMPLETE]: {
		name: 'Accept Autocomplete Generation\nJump to Prompt Variable',
		keys: ['Tab'],
		category: 'Input'
	},
	[Shortcut.PREVENT_FILE_CREATION]: {
		name: 'Prevent File Creation',
		keys: ['mod', 'shift', 'V'],
		category: 'Input',
		tooltip: 'Only active when "Paste Large Text as File" setting is toggled on.'
	},
	[Shortcut.ATTACH_FILE]: {
		name: 'Attach File From Knowledge',
		keys: ['#'],
		category: 'Input'
	},
	[Shortcut.ADD_PROMPT]: {
		name: 'Add Custom Prompt',
		keys: ['/'],
		category: 'Input'
	},
	[Shortcut.TALK_TO_MODEL]: {
		name: 'Talk to Model',
		keys: ['@'],
		category: 'Input'
	},

	//Message
	[Shortcut.GENERATE_MESSAGE_PAIR]: {
		name: 'Generate Message Pair',
		keys: ['mod', 'shift', 'Enter'],
		category: 'Message',
		configurable: true,
		tooltip: 'Only active when the chat input is in focus.'
	},
	[Shortcut.REGENERATE_RESPONSE]: {
		name: 'Regenerate Response',
		keys: ['mod', 'R'],
		category: 'Message',
		configurable: true
	},
	[Shortcut.STOP_GENERATING]: {
		name: 'Stop Generating',
		keys: ['Escape'],
		category: 'Message',
		tooltip: 'Only active when the chat input is in focus and an LLM is generating a response.'
	},
	[Shortcut.NAVIGATE_PROMPT_HISTORY_UP]: {
		name: 'Edit Last Message',
		keys: ['ArrowUp'],
		category: 'Message',
		tooltip: 'Only can be triggered when the chat input is in focus.'
	},
	[Shortcut.COPY_LAST_RESPONSE]: {
		name: 'Copy Last Response',
		keys: ['mod', 'shift', 'C'],
		category: 'Message',
		configurable: true
	},
	[Shortcut.COPY_LAST_CODE_BLOCK]: {
		name: 'Copy Last Code Block',
		keys: ['mod', 'shift', ';'],
		category: 'Message',
		configurable: true
	},

	//Voice
	[Shortcut.TOGGLE_MUTE]: {
		name: 'Toggle Mute',
		keys: ['M'],
		category: 'Voice',
		tooltip: 'Only active during Voice Mode.'
	}
};
