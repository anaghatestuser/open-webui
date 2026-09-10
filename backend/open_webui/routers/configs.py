from __future__ import annotations
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

import copy
import logging
from typing import Optional

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Request
from mcp.shared.auth import OAuthMetadata
from open_webui.config import BannerModel
from open_webui.env import AIOHTTP_CLIENT_SESSION_SSL, AIOHTTP_CLIENT_TIMEOUT
from open_webui.events import EVENTS, publish_event
from open_webui.models.config import Config
from open_webui.models.oauth_sessions import OAuthSessions
from open_webui.utils.auth import get_admin_user, get_verified_user
from open_webui.utils.headers import get_custom_headers
from open_webui.utils.mcp.client import MCPClient
from open_webui.utils.oauth import (
    OAuthClientInformationFull,
    apply_connection_oauth_options,
    decrypt_data,
    encrypt_data,
    get_discovery_urls,
    get_oauth_client_info_with_dynamic_client_registration,
    get_oauth_client_info_with_static_credentials,
    recover_static_oauth_client_metadata,
    resolve_oauth_client_info,
)
from open_webui.utils.tools import (
    bearer_auth_header,
    get_tool_server_data,
    get_tool_server_url,
    set_terminal_servers,
    set_tool_servers,
)
from pydantic import BaseModel, ConfigDict

router = APIRouter()

log = logging.getLogger(__name__)

CONNECTIONS_CONFIG_KEYS = {
    'ENABLE_DIRECT_CONNECTIONS': 'direct.enable',
    'ENABLE_BASE_MODELS_CACHE': 'models.base_models_cache',
}
CODE_EXECUTION_CONFIG_KEYS = {
    'ENABLE_CODE_EXECUTION': 'code_execution.enable',
    'CODE_EXECUTION_ENGINE': 'code_execution.engine',
    'CODE_EXECUTION_JUPYTER_URL': 'code_execution.jupyter.url',
    'CODE_EXECUTION_JUPYTER_AUTH': 'code_execution.jupyter.auth',
    'CODE_EXECUTION_JUPYTER_AUTH_TOKEN': 'code_execution.jupyter.auth_token',
    'CODE_EXECUTION_JUPYTER_AUTH_PASSWORD': 'code_execution.jupyter.auth_password',
    'CODE_EXECUTION_JUPYTER_TIMEOUT': 'code_execution.jupyter.timeout',
    'ENABLE_CODE_INTERPRETER': 'code_interpreter.enable',
    'CODE_INTERPRETER_ENGINE': 'code_interpreter.engine',
    'CODE_INTERPRETER_PROMPT_TEMPLATE': 'code_interpreter.prompt_template',
    'CODE_INTERPRETER_JUPYTER_URL': 'code_interpreter.jupyter.url',
    'CODE_INTERPRETER_JUPYTER_AUTH': 'code_interpreter.jupyter.auth',
    'CODE_INTERPRETER_JUPYTER_AUTH_TOKEN': 'code_interpreter.jupyter.auth_token',
    'CODE_INTERPRETER_JUPYTER_AUTH_PASSWORD': 'code_interpreter.jupyter.auth_password',
    'CODE_INTERPRETER_JUPYTER_TIMEOUT': 'code_interpreter.jupyter.timeout',
}
MODELS_CONFIG_KEYS = {
    'DEFAULT_MODELS': 'ui.default_models',
    'DEFAULT_PINNED_MODELS': 'ui.default_pinned_models',
    'MODEL_ORDER_LIST': 'ui.model_order_list',
    'DEFAULT_MODEL_METADATA': 'models.default_metadata',
    'DEFAULT_MODEL_PARAMS': 'models.default_params',
}
SUBAGENTS_CONFIG_KEYS = {
    'ENABLE_SUBAGENTS': 'subagents.enable',
    'SUBAGENTS_BACKGROUND_ENABLED': 'subagents.background_enabled',
    'SUBAGENTS_MAX_CONCURRENT': 'subagents.max_concurrent',
    'SUBAGENTS_MAX_ASYNC': 'subagents.max_async',
    'SUBAGENTS_MAX_ITERATIONS': 'subagents.max_iterations',
    'SUBAGENTS_MAX_OUTPUT': 'subagents.max_output',
    'SUBAGENTS_SYSTEM_PROMPT': 'subagents.system_prompt',
}


async def get_config_values(key_map: dict[str, str]) -> dict:
    values = await Config.get_many(*key_map.values())
    return {field: values[storage_key] for field, storage_key in key_map.items() if storage_key in values}


def config_updates(data: dict, key_map: dict[str, str]) -> dict:
    return {key_map[field]: value for field, value in data.items() if field in key_map}


############################
# ImportConfig
# Thy configuration come, thy settings be done,
# in production as it is in development.
############################


class ImportConfigForm(BaseModel):
    config: dict


@router.post('/import', response_model=dict)
async def import_config(request: Request, form_data: ImportConfigForm, user=Depends(get_admin_user)):
    await Config.upsert(form_data.config)
    await publish_event(
        request,
        EVENTS.CONFIG_IMPORTED,
        actor=user,
        subject_id='import',
        data={'keys': list(form_data.config.keys())},
    )
    return await Config.get_all()


############################
# ExportConfig
############################


@router.get('/export', response_model=dict)
async def export_config(user=Depends(get_admin_user)):
    return await Config.get_all()


@router.get('/namespace/{namespace}', response_model=dict)
async def get_config_namespace(namespace: str, user=Depends(get_admin_user)):
    return await Config.get_namespace(namespace)


############################
# Connections Config
############################


class ConnectionsConfigForm(BaseModel):
    ENABLE_DIRECT_CONNECTIONS: bool
    ENABLE_BASE_MODELS_CACHE: bool


@router.get('/connections', response_model=ConnectionsConfigForm)
async def get_connections_config(request: Request, user=Depends(get_admin_user)):
    return await get_config_values(CONNECTIONS_CONFIG_KEYS)


@router.post('/connections', response_model=ConnectionsConfigForm)
async def set_connections_config(
    request: Request,
    form_data: ConnectionsConfigForm,
    user=Depends(get_admin_user),
):
    await Config.upsert(config_updates(form_data.model_dump(), CONNECTIONS_CONFIG_KEYS))
    values = await get_config_values(CONNECTIONS_CONFIG_KEYS)
    await publish_event(
        request,
        EVENTS.CONFIG_CONNECTIONS_UPDATED,
        actor=user,
        subject_id='connections',
        subject_type='config',
        data=values,
    )
    return values


class OAuthClientRegistrationForm(BaseModel):
    url: str
    client_id: str
    client_name: str | None = None
    client_secret: str | None = None
    oauth_server_url: str | None = None
    oauth_scope: str | None = None


@router.post('/oauth/clients/register')
async def register_oauth_client(
    request: Request,
    form_data: OAuthClientRegistrationForm,
    type: str | None = None,
    user=Depends(get_admin_user),
):
    try:
        oauth_client_id = form_data.client_id
        if type:
            oauth_client_id = f'{type}:{form_data.client_id}'

        oauth_server_url = form_data.oauth_server_url if form_data.oauth_server_url else form_data.url

        if form_data.client_secret:
            # Static credentials: skip dynamic registration, build from provided credentials
            oauth_client_info = await get_oauth_client_info_with_static_credentials(
                request,
                oauth_client_id,
                oauth_server_url,
                oauth_client_id=form_data.client_id,
                oauth_client_secret=form_data.client_secret,
                oauth_scope=form_data.oauth_scope,
            )
        else:
            oauth_client_info = await get_oauth_client_info_with_dynamic_client_registration(
                request, oauth_client_id, oauth_server_url, oauth_scope=form_data.oauth_scope
            )
        return {
            'status': True,
            'oauth_client_info': encrypt_data(oauth_client_info.model_dump(mode='json')),
        }
    except Exception as e:
        _lineaje_payload = f'Failed to register OAuth client: {e}'
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:06400625019227e3530b379d118ac00fe3333c7a0e89bbaaa2244b80bb436493')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        log.debug(f'Failed to register OAuth client: {e}')
        raise HTTPException(
            status_code=400,
            detail=f'Failed to register OAuth client: {e}',
        )


############################
# ToolServers Config
############################


class ToolServerConnection(BaseModel):
    url: str
    path: str
    type: str | None = 'openapi'  # openapi, mcp
    auth_type: str | None
    headers: dict | str | None = None
    key: str | None
    config: dict | None
    info: dict | None = None

    model_config = ConfigDict(extra='allow')


class ToolServersConfigForm(BaseModel):
    TOOL_SERVER_CONNECTIONS: list[ToolServerConnection]


@router.get('/tool_servers', response_model=ToolServersConfigForm)
async def get_tool_servers_config(request: Request, user=Depends(get_admin_user)):
    return {'TOOL_SERVER_CONNECTIONS': await Config.get('tool_server.connections')}


@router.post('/tool_servers', response_model=ToolServersConfigForm)
async def set_tool_servers_config(
    request: Request,
    form_data: ToolServersConfigForm,
    user=Depends(get_admin_user),
):
    existing_connections = await Config.get('tool_server.connections', []) or []
    for connection in existing_connections:
        server_type = connection.get('type', 'openapi')
        auth_type = connection.get('auth_type', 'none')

        if auth_type in ('oauth_2.1', 'oauth_2.1_static'):
            # Remove existing OAuth clients for tool servers
            server_id = (connection.get('info') or {}).get('id')
            try:
                import asyncio as _gr_asyncio
                server_id = await _gr_asyncio.to_thread(gr_check, server_id, "api", "agent", candidate_policies=['AI_APP_SEC_064', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005'], site_id='site:sha256:8be3b81f9d889110582a17d31b4a0ecab07ef0dc48b3bf05468a8140f4cf30f2')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                server_id = server_id
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'api->agent' — passing data through unchecked")
            client_key = f'{server_type}:{server_id}'

            try:
                request.app.state.oauth_client_manager.remove_client(client_key)
            except Exception:
                pass

    # Set new tool server connections
    connections = [connection.model_dump() for connection in form_data.TOOL_SERVER_CONNECTIONS]
    await Config.upsert({'tool_server.connections': connections})

    await set_tool_servers(request)

    for connection in connections:
        server_type = connection.get('type', 'openapi')
        if server_type == 'mcp':
            server_id = (connection.get('info') or {}).get('id')
            try:
                import asyncio as _gr_asyncio
                server_id = await _gr_asyncio.to_thread(gr_check, server_id, "api", "agent", candidate_policies=['AI_APP_SEC_064', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005'], site_id='site:sha256:0e193ca59e869e4ef2b38cf962d51e97d858ac8d725921308ef49d27c708b0a5')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                server_id = server_id
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'api->agent' — passing data through unchecked")
            auth_type = connection.get('auth_type', 'none')

            if auth_type in ('oauth_2.1', 'oauth_2.1_static') and server_id:
                try:
                    oauth_client_info = resolve_oauth_client_info(connection)
                    oauth_client_info = await recover_static_oauth_client_metadata(connection, oauth_client_info)
                    oauth_client_info = apply_connection_oauth_options(connection, oauth_client_info)
                    request.app.state.oauth_client_manager.add_client(
                        f'{server_type}:{server_id}',
                        OAuthClientInformationFull(**oauth_client_info),
                    )
                except Exception as e:
                    _lineaje_payload = f'Failed to add OAuth client for MCP tool server: {e}'
                    try:
                        import asyncio as _gr_asyncio
                        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:a8b14b6852e666a54262596f6b1d4d307e84b141165f2d45110d0501883ca8ac')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        _lineaje_payload = _lineaje_payload
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                    log.debug(f'Failed to add OAuth client for MCP tool server: {e}')
                    continue

    await publish_event(
        request,
        EVENTS.CONFIG_TOOL_SERVERS_UPDATED,
        actor=user,
        subject_id='tool_server.connections',
        subject_type='config',
        data={'count': len(connections), 'types': [connection.get('type', 'openapi') for connection in connections]},
    )
    return {'TOOL_SERVER_CONNECTIONS': connections}


class TerminalServerConnection(BaseModel):
    id: str | None = ''
    name: str | None = ''

    enabled: bool | None = True

    url: str
    path: str | None = '/openapi.json'

    key: str | None = ''
    auth_type: str | None = 'bearer'

    config: dict | None = None

    server_type: str | None = None
    policy_id: str | None = None

    model_config = ConfigDict(extra='allow')


class TerminalServersConfigForm(BaseModel):
    TERMINAL_SERVER_CONNECTIONS: list[TerminalServerConnection]


@router.get('/terminal_servers')
async def get_terminal_servers_config(request: Request, user=Depends(get_admin_user)):
    return {'TERMINAL_SERVER_CONNECTIONS': await Config.get('terminal_server.connections')}


@router.post('/terminal_servers')
async def set_terminal_servers_config(
    request: Request,
    form_data: TerminalServersConfigForm,
    user=Depends(get_admin_user),
):
    connections = [
        connection.model_dump(exclude={'policy', 'lifecycle'}) for connection in form_data.TERMINAL_SERVER_CONNECTIONS
    ]
    await Config.upsert({'terminal_server.connections': connections})

    await set_terminal_servers(request)

    await publish_event(
        request,
        EVENTS.CONFIG_TERMINAL_SERVERS_UPDATED,
        actor=user,
        subject_id='terminal_server.connections',
        subject_type='config',
        data={'count': len(connections)},
    )
    return {'TERMINAL_SERVER_CONNECTIONS': connections}


@router.post('/terminal_servers/verify')
async def verify_terminal_server_connection(
    request: Request, form_data: TerminalServerConnection, user=Depends(get_admin_user)
):
    """
    Verify the connection to a terminal server by detecting its type.

    Tries GET {url}/api/v1/policies (orchestrator) then GET {url}/api/config
    (plain terminal).  Returns ``{status: true, type: "orchestrator"|"terminal"}``.
    """
    base_url = (form_data.url or '').rstrip('/')
    if not base_url:
        raise HTTPException(status_code=400, detail='Terminal server URL is required')

    headers = {}
    if form_data.auth_type == 'bearer' and form_data.key:
        headers.update(bearer_auth_header(form_data.key))

    try:
        async with aiohttp.ClientSession(
            trust_env=True,
            timeout=aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT),
        ) as session:
            # Orchestrators expose a policies API; plain terminals don't.
            try:
                async with session.get(
                    f'{base_url}/api/v1/policies', headers=headers, ssl=AIOHTTP_CLIENT_SESSION_SSL
                ) as resp:
                    if resp.ok:
                        return {'status': True, 'type': 'orchestrator'}
            except Exception:
                pass

            # Fall back to open-terminal config endpoint.
            try:
                async with session.get(
                    f'{base_url}/api/config', headers=headers, ssl=AIOHTTP_CLIENT_SESSION_SSL
                ) as resp:
                    if resp.ok:
                        return {'status': True, 'type': 'terminal'}
            except Exception:
                pass

    except Exception as e:
        _lineaje_payload = f'Failed to connect to the terminal server: {e}'
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:8a9c7f2dab3b83a06b2509054bfd558d34d8d26925f63ca1e2a4cdfe8443ee07')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        log.debug(f'Failed to connect to the terminal server: {e}')

    raise HTTPException(status_code=400, detail='Failed to connect to the terminal server')


class TerminalServerPolicyForm(BaseModel):
    url: str
    key: str | None = ''
    auth_type: str | None = 'bearer'
    policy_id: str
    policy_data: dict | None = None


class TerminalServerLifecycleForm(BaseModel):
    url: str
    key: str | None = ''
    auth_type: str | None = 'bearer'
    policy_id: str
    lifecycle_data: dict | None = None


class TerminalServerRefreshForm(BaseModel):
    url: str
    key: str | None = ''
    auth_type: str | None = 'bearer'
    user_id: str | None = None
    policy_id: str | None = None
    only_idle: bool = True
    reset: bool = False


@router.post('/terminal_servers/policy')
async def put_terminal_server_policy(
    request: Request, form_data: TerminalServerPolicyForm, user=Depends(get_admin_user)
):
    """Proxy a policy read or update to an orchestrator terminal server."""
    base_url = (form_data.url or '').rstrip('/')
    if not base_url:
        raise HTTPException(status_code=400, detail='Terminal server URL is required')

    headers = {'Content-Type': 'application/json'}
    if form_data.auth_type == 'bearer' and form_data.key:
        headers.update(bearer_auth_header(form_data.key))

    try:
        async with aiohttp.ClientSession(
            trust_env=True,
            timeout=aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT),
        ) as session:
            policy_url = f'{base_url}/api/v1/policies/{form_data.policy_id}'
            async with session.request(
                'GET' if form_data.policy_data is None else 'PUT',
                policy_url,
                headers=headers,
                json=form_data.policy_data,
                ssl=AIOHTTP_CLIENT_SESSION_SSL,
            ) as resp:
                if resp.ok:
                    return await resp.json()
                detail = await resp.text()
                raise HTTPException(status_code=resp.status, detail=detail)
    except HTTPException:
        raise
    except Exception as e:
        _lineaje_payload = f'Failed to access policy on terminal server: {e}'
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:8a9c7f2dab3b83a06b2509054bfd558d34d8d26925f63ca1e2a4cdfe8443ee07')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        log.debug(f'Failed to access policy on terminal server: {e}')
        raise HTTPException(status_code=400, detail='Failed to access policy on terminal server')


@router.post('/terminal_servers/lifecycle')
async def put_terminal_server_lifecycle(
    request: Request, form_data: TerminalServerLifecycleForm, user=Depends(get_admin_user)
):
    """Proxy a lifecycle read or update to an orchestrator terminal server."""
    base_url = (form_data.url or '').rstrip('/')
    if not base_url:
        raise HTTPException(status_code=400, detail='Terminal server URL is required')

    headers = {'Content-Type': 'application/json'}
    if form_data.auth_type == 'bearer' and form_data.key:
        headers.update(bearer_auth_header(form_data.key))

    try:
        async with aiohttp.ClientSession(
            trust_env=True,
            timeout=aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT),
        ) as session:
            lifecycle_url = f'{base_url}/api/v1/policies/{form_data.policy_id}/lifecycle'
            async with session.request(
                'GET' if form_data.lifecycle_data is None else 'PUT',
                lifecycle_url,
                headers=headers,
                json=form_data.lifecycle_data,
                ssl=AIOHTTP_CLIENT_SESSION_SSL,
            ) as resp:
                if resp.ok:
                    return await resp.json()
                detail = await resp.text()
                raise HTTPException(status_code=resp.status, detail=detail)
    except HTTPException:
        raise
    except Exception as e:
        _lineaje_payload = f'Failed to access lifecycle on terminal server: {e}'
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:8a9c7f2dab3b83a06b2509054bfd558d34d8d26925f63ca1e2a4cdfe8443ee07')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        log.debug(f'Failed to access lifecycle on terminal server: {e}')
        raise HTTPException(status_code=400, detail='Failed to access lifecycle on terminal server')


@router.post('/terminal_servers/refresh')
async def refresh_terminal_server_terminals(
    request: Request, form_data: TerminalServerRefreshForm, user=Depends(get_admin_user)
):
    """
    Proxy a terminal refresh request to an orchestrator terminal server.
    """
    base_url = (form_data.url or '').rstrip('/')
    if not base_url:
        raise HTTPException(status_code=400, detail='Terminal server URL is required')

    headers = {'Content-Type': 'application/json'}
    if form_data.auth_type == 'bearer' and form_data.key:
        headers.update(bearer_auth_header(form_data.key))

    body = {
        'only_idle': form_data.only_idle,
        'reset': form_data.reset,
    }
    if form_data.user_id:
        body['user_id'] = form_data.user_id
    if form_data.policy_id:
        body['policy_id'] = form_data.policy_id

    try:
        async with aiohttp.ClientSession(
            trust_env=True,
            timeout=aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT),
        ) as session:
            refresh_url = f'{base_url}/api/v1/terminals/refresh'
            async with session.post(
                refresh_url,
                headers=headers,
                json=body,
                ssl=AIOHTTP_CLIENT_SESSION_SSL,
            ) as resp:
                if resp.ok:
                    return await resp.json()
                detail = await resp.text()
                raise HTTPException(status_code=resp.status, detail=detail)
    except HTTPException:
        raise
    except Exception as e:
        _lineaje_payload = f'Failed to refresh terminals: {e}'
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:8a9c7f2dab3b83a06b2509054bfd558d34d8d26925f63ca1e2a4cdfe8443ee07')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        log.debug(f'Failed to refresh terminals: {e}')
        raise HTTPException(status_code=400, detail='Failed to refresh terminals')


@router.post('/tool_servers/verify')
async def verify_tool_servers_config(request: Request, form_data: ToolServerConnection, user=Depends(get_admin_user)):
    """
    Verify the connection to the tool server.
    """
    try:
        if form_data.type == 'mcp':
            if form_data.auth_type in ('oauth_2.1', 'oauth_2.1_static'):
                oauth_server_url = (
                    form_data.info.get('oauth_server_url')
                    if form_data.info and form_data.info.get('oauth_server_url')
                    else form_data.url
                )
                discovery_urls = await get_discovery_urls(oauth_server_url)
                for discovery_url in discovery_urls:
                    _lineaje_payload = f'Trying to fetch OAuth 2.1 discovery document from {discovery_url}'
                    try:
                        import asyncio as _gr_asyncio
                        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:0dec991026260e5e8b1fda3d761aaadc5dd9f8df3211ffec0b5c7dd52453a85d')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        _lineaje_payload = _lineaje_payload
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                    log.debug(f'Trying to fetch OAuth 2.1 discovery document from {discovery_url}')
                    async with aiohttp.ClientSession(
                        trust_env=True,
                        timeout=aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT),
                    ) as session:
                        async with session.get(
                            discovery_url, ssl=AIOHTTP_CLIENT_SESSION_SSL
                        ) as oauth_server_metadata_response:
                            if oauth_server_metadata_response.status == 200:
                                try:
                                    oauth_server_metadata = OAuthMetadata.model_validate(
                                        await oauth_server_metadata_response.json()
                                    )
                                    return {
                                        'status': True,
                                        'oauth_server_metadata': oauth_server_metadata.model_dump(mode='json'),
                                    }
                                except Exception as e:
                                    _lineaje_payload = f'Failed to parse OAuth 2.1 discovery document: {e}'
                                    try:
                                        import asyncio as _gr_asyncio
                                        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:9f94e8245f042a4af354bc8a67d33ed074abd7695435ae2729465564187873e1')
                                    except Exception as _gr_exc:
                                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                                        _lineaje_payload = _lineaje_payload
                                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                                    log.info(f'Failed to parse OAuth 2.1 discovery document: {e}')
                                    raise HTTPException(
                                        status_code=400,
                                        detail=f'Failed to parse OAuth 2.1 discovery document from {discovery_url}',
                                    )

                raise HTTPException(
                    status_code=400,
                    detail=f'Failed to fetch OAuth 2.1 discovery document from {discovery_urls}',
                )
            else:
                try:
                    client = MCPClient()
                    headers = None

                    token = None
                    if form_data.auth_type == 'bearer':
                        token = form_data.key
                    elif form_data.auth_type == 'session':
                        token = request.state.token.credentials
                    elif form_data.auth_type == 'system_oauth':
                        oauth_token = None
                        try:
                            if request.cookies.get('oauth_session_id', None):
                                oauth_token = await request.app.state.oauth_manager.get_oauth_token(
                                    user.id,
                                    request.cookies.get('oauth_session_id', None),
                                )

                                if oauth_token:
                                    token = oauth_token.get('access_token', '')
                        except Exception as e:
                            pass
                    if token:
                        headers = {'Authorization': f'Bearer {token}'}

                    if form_data.headers and isinstance(form_data.headers, dict):
                        if headers is None:
                            headers = {}
                        custom_headers = await get_custom_headers(form_data.headers, user)
                        headers.update(custom_headers)

                    await client.connect(form_data.url, headers=headers)
                    specs = await client.list_tool_specs()
                    return {
                        'status': True,
                        'specs': specs,
                    }
                except Exception as e:
                    _lineaje_payload = f'Failed to create MCP client: {e}'
                    try:
                        import asyncio as _gr_asyncio
                        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:8a9c7f2dab3b83a06b2509054bfd558d34d8d26925f63ca1e2a4cdfe8443ee07')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        _lineaje_payload = _lineaje_payload
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                    log.debug(f'Failed to create MCP client: {e}')
                    raise HTTPException(
                        status_code=400,
                        detail=f'Failed to create MCP client',
                    )
                finally:
                    if client:
                        await client.disconnect()
        else:  # openapi
            token = None
            headers = None
            if form_data.auth_type == 'bearer':
                token = form_data.key
            elif form_data.auth_type == 'session':
                token = request.state.token.credentials
            elif form_data.auth_type == 'system_oauth':
                try:
                    if request.cookies.get('oauth_session_id', None):
                        oauth_token = await request.app.state.oauth_manager.get_oauth_token(
                            user.id,
                            request.cookies.get('oauth_session_id', None),
                        )

                        if oauth_token:
                            token = oauth_token.get('access_token', '')

                except Exception as e:
                    pass

            if token:
                headers = {'Authorization': f'Bearer {token}'}

            if form_data.headers and isinstance(form_data.headers, dict):
                if headers is None:
                    headers = {}
                custom_headers = await get_custom_headers(form_data.headers, user)
                headers.update(custom_headers)

            url = get_tool_server_url(form_data.url, form_data.path)
            return await get_tool_server_data(url, headers=headers)
    except HTTPException as e:
        raise e
    except Exception as e:
        _lineaje_payload = f'Failed to connect to the tool server: {e}'
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:51beb7b5cb1f508aebf3cf852c6571de5f9297f6694cc1720d25343c7e03df13')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        log.debug(f'Failed to connect to the tool server: {e}')
        raise HTTPException(
            status_code=400,
            detail=f'Failed to connect to the tool server',
        )


############################
# CodeInterpreterConfig
############################
class CodeInterpreterConfigForm(BaseModel):
    ENABLE_CODE_EXECUTION: bool
    CODE_EXECUTION_ENGINE: str
    CODE_EXECUTION_JUPYTER_URL: str | None
    CODE_EXECUTION_JUPYTER_AUTH: str | None
    CODE_EXECUTION_JUPYTER_AUTH_TOKEN: str | None
    CODE_EXECUTION_JUPYTER_AUTH_PASSWORD: str | None
    CODE_EXECUTION_JUPYTER_TIMEOUT: int | None
    ENABLE_CODE_INTERPRETER: bool
    CODE_INTERPRETER_ENGINE: str
    CODE_INTERPRETER_PROMPT_TEMPLATE: str | None
    CODE_INTERPRETER_JUPYTER_URL: str | None
    CODE_INTERPRETER_JUPYTER_AUTH: str | None
    CODE_INTERPRETER_JUPYTER_AUTH_TOKEN: str | None
    CODE_INTERPRETER_JUPYTER_AUTH_PASSWORD: str | None
    CODE_INTERPRETER_JUPYTER_TIMEOUT: int | None


@router.get('/code_execution', response_model=CodeInterpreterConfigForm)
async def get_code_execution_config(request: Request, user=Depends(get_admin_user)):
    return await get_config_values(CODE_EXECUTION_CONFIG_KEYS)


@router.post('/code_execution', response_model=CodeInterpreterConfigForm)
async def set_code_execution_config(
    request: Request, form_data: CodeInterpreterConfigForm, user=Depends(get_admin_user)
):
    await Config.upsert(config_updates(form_data.model_dump(), CODE_EXECUTION_CONFIG_KEYS))
    values = await get_config_values(CODE_EXECUTION_CONFIG_KEYS)
    await publish_event(
        request,
        EVENTS.CONFIG_CODE_EXECUTION_UPDATED,
        actor=user,
        subject_id='code_execution',
        subject_type='config',
        data={
            'code_execution_enabled': values.get('ENABLE_CODE_EXECUTION'),
            'code_execution_engine': values.get('CODE_EXECUTION_ENGINE'),
            'code_interpreter_enabled': values.get('ENABLE_CODE_INTERPRETER'),
            'code_interpreter_engine': values.get('CODE_INTERPRETER_ENGINE'),
        },
    )
    return values


############################
# SetDefaultModels
############################
class ModelsConfigForm(BaseModel):
    DEFAULT_MODELS: str | None
    DEFAULT_PINNED_MODELS: str | None
    MODEL_ORDER_LIST: list[str | None]
    DEFAULT_MODEL_METADATA: dict | None = None
    DEFAULT_MODEL_PARAMS: dict | None = None


@router.get('/models/defaults')
async def get_models_defaults(request: Request, user=Depends(get_verified_user)):
    return {
        'DEFAULT_MODEL_METADATA': await Config.get('models.default_metadata'),
    }


@router.get('/models', response_model=ModelsConfigForm)
async def get_models_config(request: Request, user=Depends(get_admin_user)):
    return await get_config_values(MODELS_CONFIG_KEYS)


@router.post('/models', response_model=ModelsConfigForm)
async def set_models_config(request: Request, form_data: ModelsConfigForm, user=Depends(get_admin_user)):
    await Config.upsert(config_updates(form_data.model_dump(), MODELS_CONFIG_KEYS))
    values = await get_config_values(MODELS_CONFIG_KEYS)
    await publish_event(
        request,
        EVENTS.CONFIG_MODELS_UPDATED,
        actor=user,
        subject_id='models',
        subject_type='config',
        data={
            'default_models': values.get('DEFAULT_MODELS'),
            'default_pinned_models': values.get('DEFAULT_PINNED_MODELS'),
            'model_order_count': len(values.get('MODEL_ORDER_LIST') or []),
        },
    )
    return values


class SubagentsConfigForm(BaseModel):
    ENABLE_SUBAGENTS: bool
    SUBAGENTS_BACKGROUND_ENABLED: bool
    SUBAGENTS_MAX_CONCURRENT: int
    SUBAGENTS_MAX_ASYNC: int
    SUBAGENTS_MAX_ITERATIONS: int
    SUBAGENTS_MAX_OUTPUT: int
    SUBAGENTS_SYSTEM_PROMPT: str


@router.get('/subagents', response_model=SubagentsConfigForm)
async def get_subagents_config(user=Depends(get_admin_user)):
    return await get_config_values(SUBAGENTS_CONFIG_KEYS)


@router.post('/subagents', response_model=SubagentsConfigForm)
async def set_subagents_config(
    request: Request,
    form_data: SubagentsConfigForm,
    user=Depends(get_admin_user),
):
    await Config.upsert(config_updates(form_data.model_dump(), SUBAGENTS_CONFIG_KEYS))
    values = await get_config_values(SUBAGENTS_CONFIG_KEYS)
    await publish_event(
        request,
        EVENTS.CONFIG_UPDATED,
        actor=user,
        subject_id='subagents',
        subject_type='config',
        data={'enabled': values.get('ENABLE_SUBAGENTS')},
    )
    try:
        import asyncio as _gr_asyncio
        values = await _gr_asyncio.to_thread(gr_check, values, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:578cdaee115505c7c3cff6685ab2eda7def2eb32e6e35d43de81561877d73eb1')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        values = values
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return values


class PromptSuggestion(BaseModel):
    title: list[str]
    content: str


class SetDefaultSuggestionsForm(BaseModel):
    suggestions: list[PromptSuggestion]


@router.post('/suggestions', response_model=list[PromptSuggestion])
async def set_default_suggestions(
    request: Request,
    form_data: SetDefaultSuggestionsForm,
    user=Depends(get_admin_user),
):
    data = form_data.model_dump()
    await Config.upsert({'ui.prompt_suggestions': data['suggestions']})
    suggestions = await Config.get('ui.prompt_suggestions')
    try:
        import asyncio as _gr_asyncio
        suggestions = await _gr_asyncio.to_thread(gr_check, suggestions, "api", "agent", candidate_policies=['AI_APP_SEC_064', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005'], site_id='site:sha256:a1502c51e40771224c62d9101dba257c7282973e03efdfaae816819f1abab519')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        suggestions = suggestions
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'api->agent' — passing data through unchecked")
    await publish_event(
        request,
        EVENTS.CONFIG_SUGGESTIONS_UPDATED,
        actor=user,
        subject_id='ui.prompt_suggestions',
        subject_type='config',
        data={'count': len(suggestions or [])},
    )
    try:
        import asyncio as _gr_asyncio
        suggestions = await _gr_asyncio.to_thread(gr_check, suggestions, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:578cdaee115505c7c3cff6685ab2eda7def2eb32e6e35d43de81561877d73eb1')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        suggestions = suggestions
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return suggestions


############################
# SetBanners
############################


class SetBannersForm(BaseModel):
    banners: list[BannerModel]


@router.post('/banners', response_model=list[BannerModel])
async def set_banners(
    request: Request,
    form_data: SetBannersForm,
    user=Depends(get_admin_user),
):
    data = form_data.model_dump()
    await Config.upsert({'ui.banners': data['banners']})
    banners = await Config.get('ui.banners')
    try:
        import asyncio as _gr_asyncio
        banners = await _gr_asyncio.to_thread(gr_check, banners, "api", "agent", candidate_policies=['AI_APP_SEC_064', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005'], site_id='site:sha256:0bc318e0c9a4b4e37785630fda0d80e1147b3b99ddcc1c19923b60ed44ac4641')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        banners = banners
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'api->agent' — passing data through unchecked")
    await publish_event(
        request,
        EVENTS.CONFIG_BANNERS_UPDATED,
        actor=user,
        subject_id='ui.banners',
        subject_type='config',
        data={'count': len(banners or [])},
    )
    try:
        import asyncio as _gr_asyncio
        banners = await _gr_asyncio.to_thread(gr_check, banners, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:578cdaee115505c7c3cff6685ab2eda7def2eb32e6e35d43de81561877d73eb1')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        banners = banners
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return banners


@router.get('/banners', response_model=list[BannerModel])
async def get_banners(
    request: Request,
    user=Depends(get_verified_user),
):
    return await Config.get('ui.banners')
