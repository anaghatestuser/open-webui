# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": data}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        req = _ur.Request(url.rstrip("/") + "/enforce", data=_j.dumps(body).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            result = _j.loads(resp.read())
    except Exception as exc:
        if isinstance(exc, _ue.HTTPError) and exc.code == 403:
            try: detail = _j.loads(exc.read()).get("detail", {})
            except Exception: detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)
import asyncio
import copy
import logging
import sys

from aiocache import cached
from fastapi import Request
from open_webui.config import (
    BYPASS_ADMIN_ACCESS_CONTROL,
    DEFAULT_ARENA_MODEL,
)
from open_webui.env import BYPASS_MODEL_ACCESS_CONTROL, ENABLE_PLUGINS, GLOBAL_LOG_LEVEL
from open_webui.functions import get_function_models
from open_webui.models.access_grants import AccessGrants
from open_webui.models.config import Config
from open_webui.models.functions import Functions
from open_webui.models.groups import Groups
from open_webui.models.models import Models
from open_webui.utils.chat_variables import get_chat_variables_schema
from open_webui.models.users import UserModel
from open_webui.routers import ollama, openai
from open_webui.socket.utils import RedisDict
from open_webui.utils.access_control import has_access, has_base_model_access
from open_webui.utils.plugin import (
    get_functions_cache,
    get_function_module_from_cache,
)

logging.basicConfig(stream=sys.stdout, level=GLOBAL_LOG_LEVEL)
log = logging.getLogger(__name__)


async def fetch_ollama_models(request: Request, user: UserModel = None):
    raw_ollama_models = await ollama.get_all_models(request, user=user)
    return [
        {
            'id': model['model'],
            'name': model['name'],
            'object': 'model',
            'created': 0,
            'owned_by': 'ollama',
            'ollama': model,
            'loaded': 'expires_at' in model,
            'connection_type': model.get('connection_type', 'local'),
            'tags': model.get('tags', []),
        }
        for model in raw_ollama_models['models']
    ]


async def fetch_openai_models(request: Request, user: UserModel = None):
    openai_response = await openai.get_all_models(request, user=user)
    return openai_response['data']


async def get_all_base_models(request: Request, user: UserModel = None):
    config = await Config.get_many('openai.enable', 'ollama.enable')
    openai_task = fetch_openai_models(request, user) if config.get('openai.enable') else asyncio.sleep(0, result=[])
    ollama_task = fetch_ollama_models(request, user) if config.get('ollama.enable') else asyncio.sleep(0, result=[])
    function_task = get_function_models(request)

    openai_models, ollama_models, function_models = await asyncio.gather(openai_task, ollama_task, function_task)

    return function_models + openai_models + ollama_models


async def get_all_models(request, refresh: bool = False, user: UserModel = None):
    config = await Config.get_many(
        'models.base_models_cache',
        'evaluation.arena.enable',
        'evaluation.arena.models',
        'models.default_metadata',
    )
    if (
        request.app.state.MODELS
        and request.app.state.BASE_MODELS
        and (config.get('models.base_models_cache') and not refresh)
    ):
        base_models = request.app.state.BASE_MODELS
    else:
        base_models = await get_all_base_models(request, user=user)
        if base_models:
            request.app.state.BASE_MODELS = base_models
        else:
            base_models = request.app.state.BASE_MODELS

    # deep copy the base models to avoid modifying the original list
    models = [model.copy() for model in base_models]

    # If there are no models, return an empty list
    if len(models) == 0:
        return []

    # Add arena models
    if config.get('evaluation.arena.enable'):
        arena_models = []
        arena_config = config.get('evaluation.arena.models') or []
        if len(arena_config) > 0:
            arena_models = [
                {
                    'id': model['id'],
                    'name': model['name'],
                    'info': {
                        'meta': model['meta'],
                    },
                    'object': 'model',
                    'created': 0,
                    'owned_by': 'arena',
                    'arena': True,
                }
                for model in arena_config
            ]
        else:
            # Add default arena model
            arena_models = [
                {
                    'id': DEFAULT_ARENA_MODEL['id'],
                    'name': DEFAULT_ARENA_MODEL['name'],
                    'info': {
                        'meta': DEFAULT_ARENA_MODEL['meta'],
                    },
                    'object': 'model',
                    'created': 0,
                    'owned_by': 'arena',
                    'arena': True,
                }
            ]
        models = models + arena_models

    # One query per type: the global sets are subsets of the active sets, so
    # deriving them from the same rows halves the function-table queries.
    if ENABLE_PLUGINS:
        active_actions = await Functions.get_active_function_ids_by_type('action')
        global_action_ids = {function_id for function_id, is_global in active_actions if is_global}
        enabled_action_ids = {function_id for function_id, _ in active_actions}

        active_filters = await Functions.get_active_function_ids_by_type('filter')
        global_filter_ids = {function_id for function_id, is_global in active_filters if is_global}
        enabled_filter_ids = {function_id for function_id, _ in active_filters}
    else:
        global_action_ids = set()
        enabled_action_ids = set()
        global_filter_ids = set()
        enabled_filter_ids = set()

    custom_models = await Models.get_all_models()

    # Single O(1) lookup: Ollama base names first, then exact IDs (exact wins).
    base_model_lookup = {}
    for model in models:
        if model.get('owned_by') == 'ollama':
            base_model_lookup.setdefault(model['id'].split(':')[0], model)
        base_model_lookup[model['id']] = model

    existing_ids = {m['id'] for m in models}

    for custom_model in custom_models:
        if custom_model.base_model_id is None:
            # Override applied directly to a base model (shares the same ID)
            model = base_model_lookup.get(custom_model.id)

            if model:
                if custom_model.is_active:
                    model['name'] = custom_model.name
                    model['info'] = custom_model.model_dump()
                    schema = get_chat_variables_schema(custom_model.params.model_dump().get('system'))
                    if schema:
                        model['info'].setdefault('meta', {})['chat_variables_schema'] = schema

                    action_ids = []
                    filter_ids = []

                    if 'info' in model:
                        if 'meta' in model['info']:
                            if ENABLE_PLUGINS:
                                action_ids.extend(model['info']['meta'].get('actionIds', []))
                                filter_ids.extend(model['info']['meta'].get('filterIds', []))

                        if 'params' in model['info']:
                            del model['info']['params']

                    model['action_ids'] = action_ids
                    model['filter_ids'] = filter_ids
                else:
                    models.remove(model)

        elif custom_model.is_active:
            if custom_model.id in existing_ids:
                continue

            owned_by = 'openai'
            connection_type = None
            pipe = None

            base_model = base_model_lookup.get(custom_model.base_model_id)
            if base_model is None:
                base_model = base_model_lookup.get(custom_model.base_model_id.split(':')[0])
            if base_model:
                owned_by = base_model.get('owned_by', 'unknown')
                if 'pipe' in base_model:
                    pipe = base_model['pipe']
                connection_type = base_model.get('connection_type', None)

            model = {
                'id': f'{custom_model.id}',
                'name': custom_model.name,
                'object': 'model',
                'created': custom_model.created_at,
                'owned_by': owned_by,
                'connection_type': connection_type,
                'preset': True,
                **({'pipe': pipe} if pipe is not None else {}),
                **({'provider': base_model.get('provider')} if base_model and base_model.get('provider') else {}),
                **({'loaded': base_model.get('loaded')} if base_model and base_model.get('loaded') is not None else {}),
            }

            info = custom_model.model_dump()
            schema = get_chat_variables_schema(custom_model.params.model_dump().get('system'))
            if schema:
                info.setdefault('meta', {})['chat_variables_schema'] = schema
            if 'params' in info:
                # Remove params to avoid exposing sensitive info
                del info['params']

            model['info'] = info

            action_ids = []
            filter_ids = []

            if custom_model.meta:
                meta = custom_model.meta.model_dump()

                if ENABLE_PLUGINS and 'actionIds' in meta:
                    action_ids.extend(meta['actionIds'])

                if ENABLE_PLUGINS and 'filterIds' in meta:
                    filter_ids.extend(meta['filterIds'])

            model['action_ids'] = action_ids
            model['filter_ids'] = filter_ids

            models.append(model)

    # Process action_ids to get the actions
    def get_action_items_from_module(function, module):
        actions = []
        if hasattr(module, 'actions'):
            actions = module.actions
            return [
                {
                    'id': f'{function.id}.{action["id"]}',
                    'name': action.get('name', f'{function.name} ({action["id"]})'),
                    'description': function.meta.description,
                    'icon': action.get(
                        'icon_url',
                        function.meta.manifest.get('icon_url', None)
                        or getattr(module, 'icon_url', None)
                        or getattr(module, 'icon', None),
                    ),
                }
                for action in actions
            ]
        else:
            return [
                {
                    'id': function.id,
                    'name': function.name,
                    'description': function.meta.description,
                    'icon': function.meta.manifest.get('icon_url', None)
                    or getattr(module, 'icon_url', None)
                    or getattr(module, 'icon', None),
                }
            ]

    # Process filter_ids to get the filters
    def get_filter_items_from_module(function, module):
        return [
            {
                'id': function.id,
                'name': function.name,
                'description': function.meta.description,
                'icon': function.meta.manifest.get('icon_url', None)
                or getattr(module, 'icon_url', None)
                or getattr(module, 'icon', None),
                'has_user_valves': hasattr(module, 'UserValves'),
            }
        ]

    # Batch-prefetch all needed function records to avoid N+1 queries
    all_function_ids = set()
    for model in models:
        all_function_ids.update(model.get('action_ids', []))
        all_function_ids.update(model.get('filter_ids', []))
    all_function_ids.update(global_action_ids)
    all_function_ids.update(global_filter_ids)

    functions_by_id = {f.id: f for f in await Functions.get_functions_by_ids(list(all_function_ids))}

    # Pre-warm the function module cache once per unique function ID.
    # This ensures each function's DB freshness check runs exactly once,
    # not once per (model × function) pair.
    # Only attempt to load functions that actually exist in the local DB;
    # imported/custom model configs may reference tools or filters the user
    # hasn't installed, and trying to load those would cause persistent
    # "Failed to load function module" log spam on every model refresh.
    for function_id, function in functions_by_id.items():
        try:
            await get_function_module_from_cache(request, function_id, function=function)
        except Exception as e:
            _lineaje_payload = f'Failed to load function module for {function_id}: {e}'
            try:
                import asyncio as _gr_asyncio
                _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:9f88908dd6c569a377ffb724e4ebb85932e1d043ef3afd1157dad370d0a4de68')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            log.debug(f'Failed to load function module for {function_id}: {e}')

    # Apply global model defaults to all models
    # Per-model overrides take precedence over global defaults
    default_metadata = config.get('models.default_metadata') or {}

    if default_metadata:
        for model in models:
            info = model.get('info')

            if info is None:
                model['info'] = {'meta': copy.deepcopy(default_metadata)}
                continue

            meta = info.setdefault('meta', {})
            for key, value in default_metadata.items():
                if key == 'capabilities':
                    # Merge capabilities: defaults as base, per-model overrides win
                    existing = meta.get('capabilities') or {}
                    meta['capabilities'] = {**value, **existing}
                elif meta.get(key) is None:
                    meta[key] = copy.deepcopy(value)

    # Batch-fetch all function valves in one query to avoid N+1 DB hits
    # inside get_action_priority (previously called per action × per model).
    all_function_valves = await Functions.get_function_valves_by_ids(list(all_function_ids))
    functions_cache = get_functions_cache(request)

    # Global actions and filters appear in every model, so priorities and item
    # lists are memoized across the loop instead of rebuilt per model.
    action_priorities = {}

    def get_action_priority(action_id):
        if action_id in action_priorities:
            return action_priorities[action_id]
        priority = 0
        try:
            function_module = functions_cache.get(action_id)
            if function_module and hasattr(function_module, 'Valves'):
                valves_db = all_function_valves.get(action_id)
                valves = function_module.Valves(**(valves_db if valves_db else {}))
                priority = getattr(valves, 'priority', 0)
        except Exception:
            priority = 0
        action_priorities[action_id] = priority
        try:
            priority = gr_check(priority, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:a0b289520f0ccfd7b710120be1e90dd6fcd7ae6ac583d94652afd14d807abff0')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            priority = priority
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return priority

    action_items_by_id = {}
    filter_items_by_id = {}

    for model in models:
        action_ids = [
            action_id
            for action_id in set(model.pop('action_ids', [])) | global_action_ids
            if action_id in enabled_action_ids
        ]
        action_ids.sort(key=lambda aid: (get_action_priority(aid), aid))

        filter_ids = [
            filter_id
            for filter_id in set(model.pop('filter_ids', [])) | global_filter_ids
            if filter_id in enabled_filter_ids
        ]

        model['actions'] = []
        for action_id in action_ids:
            items = action_items_by_id.get(action_id)
            if items is None:
                action_function = functions_by_id.get(action_id)
                if action_function is None:
                    _lineaje_payload = f'Action not found: {action_id}'
                    try:
                        import asyncio as _gr_asyncio
                        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:f125a97a0f96193481f02b4dc2f58a27bbaefafc9bcb40e95c3d055c63e6cd29')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        _lineaje_payload = _lineaje_payload
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                    log.info(f'Action not found: {action_id}')
                    action_items_by_id[action_id] = []
                    continue

                function_module = functions_cache.get(action_id)
                if function_module is None:
                    _lineaje_payload = f'Failed to load action module: {action_id}'
                    try:
                        import asyncio as _gr_asyncio
                        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:f125a97a0f96193481f02b4dc2f58a27bbaefafc9bcb40e95c3d055c63e6cd29')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        _lineaje_payload = _lineaje_payload
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                    log.info(f'Failed to load action module: {action_id}')
                    action_items_by_id[action_id] = []
                    continue
                items = get_action_items_from_module(action_function, function_module)
                action_items_by_id[action_id] = items
            # Shallow copies keep per-model item dicts independent, as before
            model['actions'].extend({**item} for item in items)

        model['filters'] = []
        for filter_id in filter_ids:
            items = filter_items_by_id.get(filter_id)
            if items is None:
                filter_function = functions_by_id.get(filter_id)
                if filter_function is None:
                    _lineaje_payload = f'Filter not found: {filter_id}'
                    try:
                        import asyncio as _gr_asyncio
                        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:f125a97a0f96193481f02b4dc2f58a27bbaefafc9bcb40e95c3d055c63e6cd29')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        _lineaje_payload = _lineaje_payload
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                    log.info(f'Filter not found: {filter_id}')
                    filter_items_by_id[filter_id] = []
                    continue

                function_module = functions_cache.get(filter_id)
                if function_module is None:
                    _lineaje_payload = f'Failed to load filter module: {filter_id}'
                    try:
                        import asyncio as _gr_asyncio
                        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:f125a97a0f96193481f02b4dc2f58a27bbaefafc9bcb40e95c3d055c63e6cd29')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        _lineaje_payload = _lineaje_payload
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                    log.info(f'Failed to load filter module: {filter_id}')
                    filter_items_by_id[filter_id] = []
                    continue
                if getattr(function_module, 'toggle', None):
                    items = get_filter_items_from_module(filter_function, function_module)
                else:
                    items = []
                filter_items_by_id[filter_id] = items
            model['filters'].extend({**item} for item in items)

    _lineaje_payload = f'get_all_models() returned {len(models)} models'
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:118c5c181d7d0089a41d678b05713e86d6370ec4e2d3056b05cad13d2f249dad')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    log.debug(f'get_all_models() returned {len(models)} models')

    models_dict = {model['id']: model for model in models}
    if isinstance(request.app.state.MODELS, RedisDict):
        try:
            request.app.state.MODELS.set(models_dict)
        except Exception as e:
            _lineaje_payload = f'Failed to update Redis model cache, using in-process cache: {e}'
            try:
                import asyncio as _gr_asyncio
                _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:99aa5ce16a5fd99683236f42286aae6460547f34b9c66468ba6841a5930d487f')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            log.warning(f'Failed to update Redis model cache, using in-process cache: {e}')
            request.app.state.MODELS = models_dict
    else:
        request.app.state.MODELS = models_dict

    try:
        import asyncio as _gr_asyncio
        models = await _gr_asyncio.to_thread(gr_check, models, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:3fcfed68e06ba6c762d3414a6f29178953c85bfbfc9463cd3aef49faf4165347')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        models = models
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return models


async def check_model_access(user, model, model_info=None, db=None):
    if model.get('arena'):
        meta = model.get('info', {}).get('meta', {})
        access_grants = meta.get('access_grants', [])
        if not await has_access(
            user.id,
            permission='read',
            access_grants=access_grants,
            db=db,
        ):
            raise Exception('Model not found')
    else:
        # Callers that already fetched the row (chat completion entry) pass it in
        if model_info is None or model_info.id != model.get('id'):
            model_info = await Models.get_model_by_id(model.get('id'), db=db)
            try:
                import asyncio as _gr_asyncio
                model_info = await _gr_asyncio.to_thread(gr_check, model_info, "api", "agent", candidate_policies=['AI_APP_SEC_064', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005'], site_id='site:sha256:e4d19d6323c66bc8c0fe1e1f87dc04f3376993703246b79968920c16083202d1')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                model_info = model_info
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'api->agent' — passing data through unchecked")
        if not model_info:
            raise Exception('Model not found')

        # One group-membership fetch shared by the direct check and every
        # base-model hop; skipped when no check below needs it.
        user_group_ids = None
        if user.id != model_info.user_id or model_info.base_model_id:
            user_group_ids = {group.id for group in await Groups.get_groups_by_member_id(user.id, db=db)}

        if not (
            user.id == model_info.user_id
            or await AccessGrants.has_access(
                user_id=user.id,
                resource_type='model',
                resource_id=model_info.id,
                permission='read',
                user_group_ids=user_group_ids,
                db=db,
            )
        ):
            raise Exception('Model not found')

        # Enforce access on chained base models
        if not await has_base_model_access(
            user.id, model_info, user_role=user.role, user_group_ids=user_group_ids, db=db
        ):
            raise Exception('Model not found')


async def get_filtered_models(models, user, db=None):
    # Filter out models that the user does not have access to
    if (
        user.role == 'user' or (user.role == 'admin' and not BYPASS_ADMIN_ACCESS_CONTROL)
    ) and not BYPASS_MODEL_ACCESS_CONTROL:
        model_infos = {}
        for model in models:
            if model.get('arena'):
                continue
            info = model.get('info')
            if info:
                model_infos[model['id']] = info

        user_group_ids = {group.id for group in await Groups.get_groups_by_member_id(user.id, db=db)}

        # Batch-fetch accessible resource IDs in a single query instead of N has_access calls
        accessible_model_ids = await AccessGrants.get_accessible_resource_ids(
            user_id=user.id,
            resource_type='model',
            resource_ids=list(model_infos.keys()),
            permission='read',
            user_group_ids=user_group_ids,
            db=db,
        )

        filtered_models = []
        for model in models:
            if model.get('arena'):
                meta = model.get('info', {}).get('meta', {})
                access_grants = meta.get('access_grants', [])
                if await has_access(
                    user.id,
                    permission='read',
                    access_grants=access_grants,
                    user_group_ids=user_group_ids,
                ):
                    filtered_models.append(model)
                continue

            model_info = model_infos.get(model['id'])
            if model_info:
                if (
                    (user.role == 'admin' and BYPASS_ADMIN_ACCESS_CONTROL)
                    or user.id == model_info.get('user_id')
                    or model['id'] in accessible_model_ids
                ):
                    filtered_models.append(model)
            elif user.role == 'admin':
                # No DB entry means no access control configured yet;
                # only admins can see unconfigured models.
                filtered_models.append(model)

        try:
            import asyncio as _gr_asyncio
            filtered_models = await _gr_asyncio.to_thread(gr_check, filtered_models, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:6e34a2dc8f90b4e36e7fca0c6b9ed224e726bde2305c7d83c4e3e27d1b20b3c3')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            filtered_models = filtered_models
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return filtered_models
    else:
        try:
            import asyncio as _gr_asyncio
            models = await _gr_asyncio.to_thread(gr_check, models, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:6e34a2dc8f90b4e36e7fca0c6b9ed224e726bde2305c7d83c4e3e27d1b20b3c3')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            models = models
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return models
