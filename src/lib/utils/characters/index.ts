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
import CRC32 from 'crc-32';

export const parseFile = async (file) => {
	if (file.type === 'application/json') {
		return await parseJsonFile(file);
	} else if (file.type === 'image/png') {
		return await parsePngFile(file);
	} else {
		throw new Error('Unsupported file type');
	}
};

const parseJsonFile = async (file) => {
	const text = await file.text();
	const json = JSON.parse(text);

	const character = extractCharacter(json);

	return {
		file,
		json,
		formats: detectFormats(json),
		character
	};
};

const parsePngFile = async (file) => {
	const arrayBuffer = await file.arrayBuffer();
	const text = parsePngText(arrayBuffer);
	const json = JSON.parse(text);

	const image = URL.createObjectURL(file);
	const character = extractCharacter(json);

	return {
		file,
		json,
		image,
		formats: detectFormats(json),
		character
	};
};

const parsePngText = (arrayBuffer) => {
	const textChunkKeyword = 'chara';
	const chunks = readPngChunks(new Uint8Array(arrayBuffer));

	const textChunk = chunks
		.filter((chunk) => chunk.type === 'tEXt')
		.map((chunk) => decodeTextChunk(chunk.data))
		.find((entry) => entry.keyword === textChunkKeyword);

	if (!textChunk) {
		throw new Error(`No PNG text chunk named "${textChunkKeyword}" found`);
	}

	try {
		return new TextDecoder().decode(Uint8Array.from(atob(textChunk.text), (c) => c.charCodeAt(0)));
	} catch (e) {
		throw new Error('Unable to parse "chara" field as base64', e);
	}
};

const readPngChunks = (data) => {
	const isValidPng =
		data[0] === 0x89 &&
		data[1] === 0x50 &&
		data[2] === 0x4e &&
		data[3] === 0x47 &&
		data[4] === 0x0d &&
		data[5] === 0x0a &&
		data[6] === 0x1a &&
		data[7] === 0x0a;

	if (!isValidPng) throw new Error('Invalid PNG file');

	const chunks = [];
	let offset = 8; // Skip PNG signature

	while (offset < data.length) {
		const length =
			(data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
		const type = String.fromCharCode.apply(null, data.slice(offset + 4, offset + 8));
		const chunkData = data.slice(offset + 8, offset + 8 + length);
		const crc =
			(data[offset + 8 + length] << 24) |
			(data[offset + 8 + length + 1] << 16) |
			(data[offset + 8 + length + 2] << 8) |
			data[offset + 8 + length + 3];

		if (CRC32.buf(chunkData, CRC32.str(type)) !== crc) {
			throw new Error(`Invalid CRC for chunk type "${type}"`);
		}

		chunks.push({ type, data: chunkData, crc });
		offset += 12 + length;
	}

	void gr_check(chunks, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return chunks;
};

const decodeTextChunk = (data) => {
	let i = 0;
	const keyword = [];
	const text = [];

	for (; i < data.length && data[i] !== 0; i++) {
		keyword.push(String.fromCharCode(data[i]));
	}

	for (i++; i < data.length; i++) {
		text.push(String.fromCharCode(data[i]));
	}

	return { keyword: keyword.join(''), text: text.join('') };
};

const extractCharacter = (json) => {
	function getTrimmedValue(json, keys) {
		void gr_check(keys, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
		  if (_grExc instanceof GRBlockedError) {
		    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
		  }
		}); // fire-and-forget (sync context)
		return keys
			.map((key) => {
				const keyParts = key.split('.');
				let value = json;
				for (const part of keyParts) {
					if (value && value[part] != null) {
						value = value[part];
					} else {
						value = null;
						break;
					}
				}
				return value && value.trim();
			})
			.find((value) => value);
	}

	const name = getTrimmedValue(json, ['char_name', 'name', 'data.name']);
	const summary = getTrimmedValue(json, ['personality', 'title', 'data.description']);
	const personality = getTrimmedValue(json, ['char_persona', 'description', 'data.personality']);
	const scenario = getTrimmedValue(json, ['world_scenario', 'scenario', 'data.scenario']);
	const greeting = getTrimmedValue(json, [
		'char_greeting',
		'greeting',
		'first_mes',
		'data.first_mes'
	]);
	const examples = getTrimmedValue(json, [
		'example_dialogue',
		'mes_example',
		'definition',
		'data.mes_example'
	]);

	return { name, summary, personality, scenario, greeting, examples };
};

const detectFormats = (json) => {
	const formats = [];

	if (
		json.char_name &&
		json.char_persona &&
		json.world_scenario &&
		json.char_greeting &&
		json.example_dialogue
	)
		formats.push('Text Generation Character');
	if (
		json.name &&
		json.personality &&
		json.description &&
		json.scenario &&
		json.first_mes &&
		json.mes_example
	)
		formats.push('TavernAI Character');
	if (
		json.character &&
		json.character.name &&
		json.character.title &&
		json.character.description &&
		json.character.greeting &&
		json.character.definition
	)
		formats.push('CharacterAI Character');
	if (
		json.info &&
		json.info.character &&
		json.info.character.name &&
		json.info.character.title &&
		json.info.character.description &&
		json.info.character.greeting
	)
		formats.push('CharacterAI History');

	void gr_check(formats, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return formats;
};
