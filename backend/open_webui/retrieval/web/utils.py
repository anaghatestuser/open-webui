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
import ipaddress
import logging
import socket
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from typing import (
    Any,
    AsyncIterator,
    Dict,
    Iterator,
    List,
    Literal,
    Optional,
    Sequence,
    Union,
)

import aiohttp
import aiohttp.resolver
import certifi
import urllib3.connection
import urllib3.connectionpool
import validators
from requests.adapters import HTTPAdapter
from fastapi.concurrency import run_in_threadpool
from langchain_community.document_loaders import PlaywrightURLLoader, WebBaseLoader
from langchain_community.document_loaders.base import BaseLoader
from langchain_core.documents import Document
from open_webui.config import (
    ENABLE_LOCAL_WEB_FETCH,
    EXTERNAL_WEB_LOADER_API_KEY,
    EXTERNAL_WEB_LOADER_URL,
    FIRECRAWL_API_BASE_URL,
    FIRECRAWL_API_KEY,
    FIRECRAWL_TIMEOUT,
    MICROSOFT_WEB_IQ_API_BASE_URL,
    MICROSOFT_WEB_IQ_API_KEY,
    MICROSOFT_WEB_IQ_LANGUAGE,
    PLAYWRIGHT_TIMEOUT,
    PLAYWRIGHT_WS_URL,
    TAVILY_API_KEY,
    TAVILY_EXTRACT_DEPTH,
    WEB_FETCH_FILTER_LIST,
    WEB_LOADER_ENGINE,
    WEB_LOADER_TIMEOUT,
)
from open_webui.constants import ERROR_MESSAGES
from open_webui.env import (
    AIOHTTP_CLIENT_ALLOW_REDIRECTS,
    AIOHTTP_CLIENT_SESSION_SSL,
    AIOHTTP_CLIENT_TIMEOUT,
    USER_AGENT,
)
from open_webui.retrieval.loaders.external_web import ExternalWebLoader
from open_webui.retrieval.loaders.microsoft_web_iq import MicrosoftWebIQLoader
from open_webui.retrieval.loaders.tavily import TavilyLoader
from open_webui.retrieval.web.firecrawl import scrape_firecrawl_url
from open_webui.utils.misc import is_host_allowed

log = logging.getLogger(__name__)


def resolve_hostname(hostname):
    # Get address information
    addr_info = socket.getaddrinfo(hostname, None)

    # Extract IP addresses from address information
    ipv4_addresses = [info[4][0] for info in addr_info if info[0] == socket.AF_INET]
    ipv6_addresses = [info[4][0] for info in addr_info if info[0] == socket.AF_INET6]

    try:
        ipv4_addresses = gr_check(ipv4_addresses, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:a1b04685a1d3f22ff3657837fc7a8ea5cd9c24d5d5109984257292c98bc96234')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        ipv4_addresses = ipv4_addresses
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return ipv4_addresses, ipv6_addresses


def _is_global_addr(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if not addr.is_global:
        return False
    if not isinstance(addr, ipaddress.IPv6Address):
        return True

    embedded = []
    if addr.ipv4_mapped:
        embedded.append(addr.ipv4_mapped)
    if addr.sixtofour:
        embedded.append(addr.sixtofour)
    if addr.teredo:
        embedded.extend(addr.teredo)

    b = addr.packed
    if b[:12] == b'\x00' * 12:
        embedded.append(ipaddress.IPv4Address(b[12:]))
    elif b[:12] == b'\x00\x64\xff\x9b' + b'\x00' * 8:
        embedded.append(ipaddress.IPv4Address(b[12:]))
    elif b[:6] == b'\x00\x64\xff\x9b\x00\x01':
        if b[8] != 0:
            return False
        embedded.append(ipaddress.IPv4Address(bytes((b[6], b[7], b[9], b[10]))))

    return all(ip.is_global for ip in embedded)


def validate_url(url: Union[str, Sequence[str]]):
    if isinstance(url, str):
        if isinstance(validators.url(url), validators.ValidationError):
            raise ValueError(ERROR_MESSAGES.INVALID_URL)

        # Reject parser-confusing chars: urlparse and requests/aiohttp split
        # on these differently, e.g. http://127.0.0.1\@1.1.1.1 → urlparse
        # extracts 1.1.1.1 (public, passes filter) while requests connects
        # to 127.0.0.1 (internal). Same shape with tab/CR/LF.
        if any(ch in url for ch in ('\\', '\t', '\n', '\r')):
            _lineaje_payload = f'Blocked URL with parser-confusing char: {url!r}'
            try:
                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:6174d1ab7c0f6cfbcfa285c1bb6144804b42f22d26aa581875b2bd1476694f97')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            log.warning(f'Blocked URL with parser-confusing char: {url!r}')
            raise ValueError(ERROR_MESSAGES.INVALID_URL)

        parsed_url = urllib.parse.urlparse(url)

        # Protocol validation - only allow http/https
        if parsed_url.scheme not in ['http', 'https']:
            _lineaje_payload = f'Blocked non-HTTP(S) protocol: {parsed_url.scheme} in URL: {url}'
            try:
                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:cbabf9ccedad21e116b39256bb45a6ecdbd29802ea0f001921c468cfa9e9e00a')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            log.warning(f'Blocked non-HTTP(S) protocol: {parsed_url.scheme} in URL: {url}')
            raise ValueError(ERROR_MESSAGES.INVALID_URL)

        # Blocklist check using unified filtering logic
        if WEB_FETCH_FILTER_LIST:
            # Match on the parsed hostname, not the full URL: a path component would
            # otherwise let any URL slip past a hostname-based block/allow entry.
            if not is_host_allowed(parsed_url.hostname, WEB_FETCH_FILTER_LIST):
                _lineaje_payload = f'URL blocked by filter list: {url}'
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:aee51640da5a4ca4af56fb82d90adbd3d76f0b8a846b21f40dbbebb265e61402')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                log.warning(f'URL blocked by filter list: {url}')
                raise ValueError(ERROR_MESSAGES.INVALID_URL)

        if not ENABLE_LOCAL_WEB_FETCH:
            # Local web fetch is disabled, filter out URLs that resolve to non-global IP addresses.
            parsed_url = urllib.parse.urlparse(url)
            # Get IPv4 and IPv6 addresses
            ipv4_addresses, ipv6_addresses = resolve_hostname(parsed_url.hostname)
            # Check if any of the resolved addresses are private
            # DNS rebinding is mitigated at the connection layer; see _SSRFSafeResolver / _SSRFSafeAdapter
            for ip in ipv4_addresses + ipv6_addresses:
                if not _is_global_addr(ip):
                    raise ValueError(ERROR_MESSAGES.INVALID_URL)
        return True
    elif isinstance(url, Sequence):
        return all(validate_url(u) for u in url)
    else:
        return False


def safe_validate_urls(url: Sequence[str]) -> Sequence[str]:
    valid_urls = []
    for u in url:
        try:
            if validate_url(u):
                valid_urls.append(u)
        except Exception as e:
            _lineaje_payload = f'Invalid URL {u}: {str(e)}'
            try:
                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:4815d63c52b4bacd166de7f74a001eb5f78a3204c0c380043d41c50409f0f64d')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            log.debug(f'Invalid URL {u}: {str(e)}')
            continue
    try:
        valid_urls = gr_check(valid_urls, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:06e07f4c272f678362bb2048b8a9742243b2d06ecb3f5fa5abb5be5c7ad4a629')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        valid_urls = valid_urls
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return valid_urls


def _ssrf_safe_new_conn(self):
    """Resolve DNS, validate all IPs are global, connect to validated IP.

    Replaces urllib3's _new_conn so the DNS lookup that feeds the actual TCP
    connect is the same one we validate — no second resolution, no rebinding
    window.
    """
    host = getattr(self, '_dns_host', self.host)
    port = self.port
    infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    if not infos:
        raise OSError(f'getaddrinfo for {host!r} returned empty list')
    if not ENABLE_LOCAL_WEB_FETCH:
        for _, _, _, _, sa in infos:
            if not _is_global_addr(sa[0]):
                raise ValueError(ERROR_MESSAGES.INVALID_URL)
    err = None
    for fam, typ, proto, _, sa in infos:
        sock = None
        try:
            sock = socket.socket(fam, typ, proto)
            if self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(self.timeout)
            if getattr(self, 'source_address', None):
                sock.bind(self.source_address)
            for opt in getattr(self, 'socket_options', None) or ():
                if len(opt) == 4 and isinstance(opt[3], str):
                    # urllib3-future per-protocol form: (level, optname, value, "tcp"/"udp")
                    if opt[3].lower() == 'tcp':
                        sock.setsockopt(*opt[:3])
                    continue
                sock.setsockopt(*opt)
            sock.connect(sa)
            try:
                sock = gr_check(sock, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:9a26ce9498519b611acfdf931e4976bac7ee2afb2f23fec5fb2379777e030f0e')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                sock = sock
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return sock
        except OSError as exc:
            err = exc
            if sock is not None:
                sock.close()
    raise err or OSError(f'connect to {host!r}:{port} failed')


class _SafeHTTPConn(urllib3.connection.HTTPConnection):
    _new_conn = _ssrf_safe_new_conn


class _SafeHTTPSConn(urllib3.connection.HTTPSConnection):
    _new_conn = _ssrf_safe_new_conn


class _SafeHTTPPool(urllib3.connectionpool.HTTPConnectionPool):
    ConnectionCls = _SafeHTTPConn


class _SafeHTTPSPool(urllib3.connectionpool.HTTPSConnectionPool):
    ConnectionCls = _SafeHTTPSConn


class _SSRFSafeAdapter(HTTPAdapter):
    """requests transport adapter that validates resolved IPs at connect time."""

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            'http': _SafeHTTPPool,
            'https': _SafeHTTPSPool,
        }


class _SSRFSafeResolver(aiohttp.resolver.DefaultResolver):
    """aiohttp resolver that rejects non-global IPs unless local fetch is on."""

    async def resolve(self, host, port=0, family=socket.AF_INET):
        results = await super().resolve(host, port, family)
        if not ENABLE_LOCAL_WEB_FETCH:
            for entry in results:
                if not _is_global_addr(entry['host']):
                    raise ValueError(ERROR_MESSAGES.INVALID_URL)
        try:
            import asyncio as _gr_asyncio
            results = await _gr_asyncio.to_thread(gr_check, results, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:b9f7d26731142b266e642fd47ddc5f9993e6e8d14739f159d8805f62cb8be9c8')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            results = results
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return results


def get_ssrf_safe_session() -> aiohttp.ClientSession:
    """A one-off aiohttp session that re-validates the connect-time IP via _SSRFSafeResolver,
    defeating DNS rebinding. Use for validate_url-gated fetches of user-supplied URLs that must
    not use the shared (rebinding-vulnerable) pool. Use as a context manager so it is closed:
    ``async with get_ssrf_safe_session() as session: ...``.
    """
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(resolver=_SSRFSafeResolver()),
        timeout=aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT),
        trust_env=True,
    )


def extract_metadata(soup, url):
    metadata = {'source': url}
    if title := soup.find('title'):
        metadata['title'] = title.get_text()
    if description := soup.find('meta', attrs={'name': 'description'}):
        metadata['description'] = description.get('content', 'No description found.')
    if html := soup.find('html'):
        metadata['language'] = html.get('lang', 'No language found.')
    try:
        metadata = gr_check(metadata, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:092c3490f0808fc1c4fe21123715cd1766bc78fca50b603145ba7820abb792cd')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        metadata = metadata
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return metadata


def verify_ssl_cert(url: str) -> bool:
    """Verify SSL certificate for the given URL."""
    if not url.startswith('https://'):
        return True

    try:
        hostname = url.split('://')[-1].split('/')[0]
        context = ssl.create_default_context(cafile=certifi.where())
        with context.wrap_socket(ssl.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
        return True
    except ssl.SSLError:
        return False
    except Exception as e:
        _lineaje_payload = f'SSL verification failed for {url}: {str(e)}'
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:a1f569b4c8f744acae870e984d0fc546bc2674f0ed2aaceeaff55de3ffb029f6')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        log.warning(f'SSL verification failed for {url}: {str(e)}')
        return False


class RateLimitMixin:
    async def _wait_for_rate_limit(self):
        """Wait to respect the rate limit if specified."""
        if self.requests_per_second and self.last_request_time:
            min_interval = timedelta(seconds=1.0 / self.requests_per_second)
            time_since_last = datetime.now() - self.last_request_time
            if time_since_last < min_interval:
                await asyncio.sleep((min_interval - time_since_last).total_seconds())
        self.last_request_time = datetime.now()

    def _sync_wait_for_rate_limit(self):
        """Synchronous version of rate limit wait."""
        if self.requests_per_second and self.last_request_time:
            min_interval = timedelta(seconds=1.0 / self.requests_per_second)
            time_since_last = datetime.now() - self.last_request_time
            if time_since_last < min_interval:
                time.sleep((min_interval - time_since_last).total_seconds())
        self.last_request_time = datetime.now()


class URLProcessingMixin:
    async def _verify_ssl_cert(self, url: str) -> bool:
        """Verify SSL certificate for a URL."""
        return await run_in_threadpool(verify_ssl_cert, url)

    async def _safe_process_url(self, url: str) -> bool:
        """Perform safety checks before processing a URL."""
        if self.verify_ssl and not await self._verify_ssl_cert(url):
            raise ValueError(f'SSL certificate verification failed for {url}')
        await self._wait_for_rate_limit()
        return True

    def _safe_process_url_sync(self, url: str) -> bool:
        """Synchronous version of safety checks."""
        if self.verify_ssl and not verify_ssl_cert(url):
            raise ValueError(f'SSL certificate verification failed for {url}')
        self._sync_wait_for_rate_limit()
        return True


class SafeFireCrawlLoader(BaseLoader, RateLimitMixin, URLProcessingMixin):
    def __init__(
        self,
        web_paths,
        verify_ssl: bool = True,
        trust_env: bool = False,
        requests_per_second: Optional[float] = None,
        continue_on_failure: bool = True,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        timeout: Optional[int] = None,
        mode: Literal['crawl', 'scrape', 'map'] = 'scrape',
        proxy: Optional[Dict[str, str]] = None,
        params: Optional[Dict] = None,
    ):
        proxy_server = proxy.get('server') if proxy else None
        if trust_env and not proxy_server:
            env_proxies = urllib.request.getproxies()
            env_proxy_server = env_proxies.get('https') or env_proxies.get('http')
            if env_proxy_server:
                if proxy:
                    proxy['server'] = env_proxy_server
                else:
                    proxy = {'server': env_proxy_server}
        self.web_paths = web_paths
        self.verify_ssl = verify_ssl
        self.requests_per_second = requests_per_second
        self.last_request_time = None
        self.trust_env = trust_env
        self.continue_on_failure = continue_on_failure
        self.api_key = api_key
        self.api_url = (api_url or 'https://api.firecrawl.dev').rstrip('/')
        self.timeout = timeout
        self.mode = mode
        self.params = params or {}

    def lazy_load(self) -> Iterator[Document]:
        for url in self.web_paths:
            try:
                self._sync_wait_for_rate_limit()
                doc = scrape_firecrawl_url(
                    self.api_url,
                    self.api_key,
                    url,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout,
                    params=self.params,
                )
                if doc is not None:
                    yield doc
            except Exception as e:
                if self.continue_on_failure:
                    _lineaje_payload = f'Error extracting content from {url} with Firecrawl: {e}'
                    try:
                        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:e264da435af3e5c50914749416e5032ea09796d6a2189cf3bd50523a2b2ea02b')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        _lineaje_payload = _lineaje_payload
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                    log.warning(f'Error extracting content from {url} with Firecrawl: {e}')
                    continue
                raise

    async def alazy_load(self):
        for url in self.web_paths:
            try:
                await self._wait_for_rate_limit()
                doc = await run_in_threadpool(
                    scrape_firecrawl_url,
                    self.api_url,
                    self.api_key,
                    url,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout,
                    params=self.params,
                )
                if doc is not None:
                    yield doc
            except Exception as e:
                if self.continue_on_failure:
                    _lineaje_payload = f'Error extracting content from {url} with Firecrawl: {e}'
                    try:
                        import asyncio as _gr_asyncio
                        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:257cb800117e34ca3e8c0d1103ed73815e61c9aa97f05a63c64ca883e2f80961')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        _lineaje_payload = _lineaje_payload
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                    log.warning(f'Error extracting content from {url} with Firecrawl: {e}')
                    continue
                raise


class SafeTavilyLoader(BaseLoader, RateLimitMixin, URLProcessingMixin):
    def __init__(
        self,
        web_paths: Union[str, List[str]],
        api_base_url: str,
        api_key: str,
        extract_depth: Literal['basic', 'advanced'] = 'basic',
        continue_on_failure: bool = True,
        requests_per_second: Optional[float] = None,
        verify_ssl: bool = True,
        trust_env: bool = False,
        proxy: Optional[Dict[str, str]] = None,
    ):
        """Initialize SafeTavilyLoader with rate limiting and SSL verification support.

        Args:
            web_paths: List of URLs/paths to process.
            api_key: The Tavily API key.
            extract_depth: Depth of extraction ("basic" or "advanced").
            continue_on_failure: Whether to continue if extraction of a URL fails.
            requests_per_second: Number of requests per second to limit to.
            verify_ssl: If True, verify SSL certificates.
            trust_env: If True, use proxy settings from environment variables.
            proxy: Optional proxy configuration.
        """
        # Initialize proxy configuration if using environment variables
        proxy_server = proxy.get('server') if proxy else None
        if trust_env and not proxy_server:
            env_proxies = urllib.request.getproxies()
            env_proxy_server = env_proxies.get('https') or env_proxies.get('http')
            if env_proxy_server:
                if proxy:
                    proxy['server'] = env_proxy_server
                else:
                    proxy = {'server': env_proxy_server}

        # Store parameters for creating TavilyLoader instances
        self.web_paths = web_paths if isinstance(web_paths, list) else [web_paths]
        self.api_base_url = api_base_url
        self.api_key = api_key
        self.extract_depth = extract_depth
        self.continue_on_failure = continue_on_failure
        self.verify_ssl = verify_ssl
        self.trust_env = trust_env
        self.proxy = proxy

        # Add rate limiting
        self.requests_per_second = requests_per_second
        self.last_request_time = None

    def lazy_load(self) -> Iterator[Document]:
        """Load documents with rate limiting support, delegating to TavilyLoader."""
        valid_urls = []
        for url in self.web_paths:
            try:
                self._safe_process_url_sync(url)
                valid_urls.append(url)
            except Exception as e:
                log.warning(f'SSL verification failed for {url}: {str(e)}')
                if not self.continue_on_failure:
                    raise e
        if not valid_urls:
            if self.continue_on_failure:
                log.warning('No valid URLs to process after SSL verification')
                return
            raise ValueError('No valid URLs to process after SSL verification')
        try:
            loader = TavilyLoader(
                urls=valid_urls,
                api_key=self.api_key,
                extract_depth=self.extract_depth,
                continue_on_failure=self.continue_on_failure,
            )
            yield from loader.lazy_load()
        except Exception as e:
            if self.continue_on_failure:
                _lineaje_payload = f'Error extracting content from URLs: {e}'
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:06d95ffe52d174ee57596c7ce669a116b58ebc936a3a2a0543cb2de2ca71abff')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                log.exception(f'Error extracting content from URLs: {e}')
            else:
                raise e

    async def alazy_load(self) -> AsyncIterator[Document]:
        """Async version with rate limiting and SSL verification."""
        valid_urls = []
        for url in self.web_paths:
            try:
                await self._safe_process_url(url)
                valid_urls.append(url)
            except Exception as e:
                _lineaje_payload = f'SSL verification failed for {url}: {str(e)}'
                try:
                    import asyncio as _gr_asyncio
                    _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:257cb800117e34ca3e8c0d1103ed73815e61c9aa97f05a63c64ca883e2f80961')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                log.warning(f'SSL verification failed for {url}: {str(e)}')
                if not self.continue_on_failure:
                    raise e

        if not valid_urls:
            if self.continue_on_failure:
                _lineaje_payload = 'No valid URLs to process after SSL verification'
                try:
                    import asyncio as _gr_asyncio
                    _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:257cb800117e34ca3e8c0d1103ed73815e61c9aa97f05a63c64ca883e2f80961')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                log.warning('No valid URLs to process after SSL verification')
                return
            raise ValueError('No valid URLs to process after SSL verification')

        try:
            loader = TavilyLoader(
                urls=valid_urls,
                api_key=self.api_key,
                extract_depth=self.extract_depth,
                continue_on_failure=self.continue_on_failure,
            )
            async for document in loader.alazy_load():
                yield document
        except Exception as e:
            if self.continue_on_failure:
                _lineaje_payload = f'Error loading URLs: {e}'
                try:
                    import asyncio as _gr_asyncio
                    _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:06d95ffe52d174ee57596c7ce669a116b58ebc936a3a2a0543cb2de2ca71abff')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                log.exception(f'Error loading URLs: {e}')
            else:
                raise e


class SafeMicrosoftWebIQLoader(BaseLoader, RateLimitMixin, URLProcessingMixin):
    def __init__(
        self,
        web_paths: Union[str, List[str]],
        api_key: str,
        language: str = 'en',
        verify_ssl: bool = True,
        trust_env: bool = False,
        requests_per_second: Optional[float] = None,
        continue_on_failure: bool = True,
        timeout: Optional[int] = None,
    ):
        self.web_paths = web_paths if isinstance(web_paths, list) else [web_paths]
        self.api_key = api_key
        self.language = language
        self.verify_ssl = verify_ssl
        self.trust_env = trust_env
        self.requests_per_second = requests_per_second
        self.last_request_time = None
        self.continue_on_failure = continue_on_failure
        self.timeout = timeout

    def lazy_load(self) -> Iterator[Document]:
        valid_urls = []
        for url in self.web_paths:
            try:
                self._safe_process_url_sync(url)
                valid_urls.append(url)
            except Exception as e:
                _lineaje_payload = f'SSL verification failed for {url}: {str(e)}'
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:e264da435af3e5c50914749416e5032ea09796d6a2189cf3bd50523a2b2ea02b')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                log.warning(f'SSL verification failed for {url}: {str(e)}')
                if not self.continue_on_failure:
                    raise e
        if not valid_urls:
            if self.continue_on_failure:
                _lineaje_payload = 'No valid URLs to process after SSL verification'
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:e264da435af3e5c50914749416e5032ea09796d6a2189cf3bd50523a2b2ea02b')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                log.warning('No valid URLs to process after SSL verification')
                return
            raise ValueError('No valid URLs to process after SSL verification')

        loader = MicrosoftWebIQLoader(
            urls=valid_urls,
            api_base_url=self.api_base_url,
            api_key=self.api_key,
            language=self.language,
            verify_ssl=self.verify_ssl,
            timeout=self.timeout,
            continue_on_failure=self.continue_on_failure,
        )
        yield from loader.lazy_load()

    async def alazy_load(self) -> AsyncIterator[Document]:
        try:
            docs = await run_in_threadpool(lambda: list(self.lazy_load()))
            for doc in docs:
                yield doc
        except Exception as e:
            if self.continue_on_failure:
                _lineaje_payload = f'Error browsing URLs with Microsoft Web IQ: {e}'
                try:
                    import asyncio as _gr_asyncio
                    _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:257cb800117e34ca3e8c0d1103ed73815e61c9aa97f05a63c64ca883e2f80961')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                log.warning(f'Error browsing URLs with Microsoft Web IQ: {e}')
            else:
                raise e


class SafePlaywrightURLLoader(PlaywrightURLLoader, RateLimitMixin, URLProcessingMixin):
    """Load HTML pages safely with Playwright, supporting SSL verification, rate limiting, and remote browser connection.

    Attributes:
        web_paths (List[str]): List of URLs to load.
        verify_ssl (bool): If True, verify SSL certificates.
        trust_env (bool): If True, use proxy settings from environment variables.
        requests_per_second (Optional[float]): Number of requests per second to limit to.
        continue_on_failure (bool): If True, continue loading other URLs on failure.
        headless (bool): If True, the browser will run in headless mode.
        proxy (dict): Proxy override settings for the Playwright session.
        playwright_ws_url (Optional[str]): WebSocket endpoint URI for remote browser connection.
        playwright_timeout (Optional[int]): Maximum operation time in milliseconds.
    """

    def __init__(
        self,
        web_paths: List[str],
        verify_ssl: bool = True,
        trust_env: bool = False,
        requests_per_second: Optional[float] = None,
        continue_on_failure: bool = True,
        headless: bool = True,
        remove_selectors: Optional[List[str]] = None,
        proxy: Optional[Dict[str, str]] = None,
        playwright_ws_url: Optional[str] = None,
        playwright_timeout: Optional[int] = 10000,
    ):
        """Initialize with additional safety parameters and remote browser support."""

        proxy_server = proxy.get('server') if proxy else None
        if trust_env and not proxy_server:
            env_proxies = urllib.request.getproxies()
            env_proxy_server = env_proxies.get('https') or env_proxies.get('http')
            if env_proxy_server:
                if proxy:
                    proxy['server'] = env_proxy_server
                else:
                    proxy = {'server': env_proxy_server}

        # We'll set headless to False if using playwright_ws_url since it's handled by the remote browser
        super().__init__(
            urls=web_paths,
            continue_on_failure=continue_on_failure,
            headless=headless if playwright_ws_url is None else False,
            remove_selectors=remove_selectors,
            proxy=proxy,
        )
        self.verify_ssl = verify_ssl
        self.requests_per_second = requests_per_second
        self.last_request_time = None
        self.playwright_ws_url = playwright_ws_url
        self.trust_env = trust_env
        self.playwright_timeout = playwright_timeout

    def _intercept_navigation_sync(self, route, request=None):
        req = request or route.request

        try:
            validate_url(req.url)
            resp = route.fetch(max_redirects=0)

            if 300 <= resp.status < 400:
                for _ in range(20):
                    if not AIOHTTP_CLIENT_ALLOW_REDIRECTS:
                        route.abort()
                        return

                    location = resp.headers.get('location')
                    if not location:
                        break

                    url = urllib.parse.urljoin(resp.url, location)
                    validate_url(url)
                    resp = route.fetch(url=url, max_redirects=0)
                    if not 300 <= resp.status < 400:
                        break
                else:
                    route.abort()
                    return
        except Exception:
            route.abort()
            return

        route.fulfill(response=resp)

    async def _intercept_navigation(self, route, request=None):
        req = request or route.request

        try:
            await run_in_threadpool(validate_url, req.url)
            resp = await route.fetch(max_redirects=0)

            if 300 <= resp.status < 400:
                for _ in range(20):
                    if not AIOHTTP_CLIENT_ALLOW_REDIRECTS:
                        await route.abort()
                        return

                    location = resp.headers.get('location')
                    if not location:
                        break

                    url = urllib.parse.urljoin(resp.url, location)
                    await run_in_threadpool(validate_url, url)
                    resp = await route.fetch(url=url, max_redirects=0)
                    if not 300 <= resp.status < 400:
                        break
                else:
                    await route.abort()
                    return
        except Exception:
            await route.abort()
            return

        await route.fulfill(response=resp)

    def lazy_load(self) -> Iterator[Document]:
        """Safely load URLs synchronously with support for remote browser."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            # Use remote browser if ws_endpoint is provided, otherwise use local browser
            if self.playwright_ws_url:
                browser = p.chromium.connect(self.playwright_ws_url)
            else:
                browser = p.chromium.launch(headless=self.headless, proxy=self.proxy)

            with browser:
                for url in self.urls:
                    try:
                        self._safe_process_url_sync(url)
                        with browser.new_page(service_workers='block') as page:
                            page.route('**/*', self._intercept_navigation_sync)
                            page.route_web_socket('**/*', lambda ws_route: ws_route.close())
                            response = page.goto(url, timeout=self.playwright_timeout)
                            if response is None:
                                raise ValueError(f'page.goto() returned None for url {url}')

                            text = self.evaluator.evaluate(page, browser, response)
                            metadata = {'source': url}
                            yield Document(page_content=text, metadata=metadata)
                    except Exception as e:
                        if self.continue_on_failure:
                            _lineaje_payload = f'Error loading {url}: {e}'
                            try:
                                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:4cedc8ef32b0f8701b3f294903b450f2a2533d25e15701d051d57d7485e53cb9')
                            except Exception as _gr_exc:
                                if type(_gr_exc).__name__ == "GRBlockedError": raise
                                _lineaje_payload = _lineaje_payload
                                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                            log.exception(f'Error loading {url}: {e}')
                            continue
                        raise e

    async def alazy_load(self) -> AsyncIterator[Document]:
        """Safely load URLs asynchronously with support for remote browser."""
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            # Use remote browser if ws_endpoint is provided, otherwise use local browser
            if self.playwright_ws_url:
                browser = await p.chromium.connect(self.playwright_ws_url)
            else:
                browser = await p.chromium.launch(headless=self.headless, proxy=self.proxy)

            async with browser:
                for url in self.urls:
                    try:
                        await self._safe_process_url(url)
                        async with await browser.new_page(service_workers='block') as page:
                            await page.route('**/*', self._intercept_navigation)
                            await page.route_web_socket('**/*', lambda ws_route: ws_route.close())
                            response = await page.goto(url, timeout=self.playwright_timeout)
                            if response is None:
                                raise ValueError(f'page.goto() returned None for url {url}')

                            text = await self.evaluator.evaluate_async(page, browser, response)
                            metadata = {'source': url}
                            yield Document(page_content=text, metadata=metadata)
                    except Exception as e:
                        if self.continue_on_failure:
                            _lineaje_payload = f'Error loading {url}: {e}'
                            try:
                                import asyncio as _gr_asyncio
                                _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:4cedc8ef32b0f8701b3f294903b450f2a2533d25e15701d051d57d7485e53cb9')
                            except Exception as _gr_exc:
                                if type(_gr_exc).__name__ == "GRBlockedError": raise
                                _lineaje_payload = _lineaje_payload
                                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                            log.exception(f'Error loading {url}: {e}')
                            continue
                        raise e


class SafeWebBaseLoader(WebBaseLoader):
    """WebBaseLoader with enhanced error handling for URLs."""

    def __init__(self, trust_env: bool = False, *args, **kwargs):
        """Initialize SafeWebBaseLoader
        Args:
            trust_env (bool, optional): set to True if using proxy to make web requests, for example
                using http(s)_proxy environment variables. Defaults to False.
        """
        # lxml parses scraped pages far faster than the html.parser default
        kwargs.setdefault('default_parser', 'lxml')
        super().__init__(*args, **kwargs)
        self.trust_env = trust_env

        # Propagate USER_AGENT env var so that both the sync _scrape() and
        # async _fetch() paths present a real UA instead of python-requests/2.x
        # which gets blocked by Cloudflare, Wikipedia, and similar bot-detection.
        # _fetch() forwards self.session.headers to the aiohttp session, so
        # setting it here covers both code-paths.
        if USER_AGENT:
            self.session.headers['User-Agent'] = USER_AGENT

        # Prevent redirect-based SSRF on the synchronous _scrape() path.
        # validate_url() is called once on the originally-submitted URL, but the
        # parent WebBaseLoader's _scrape() invokes self.session.get(url, **self.requests_kwargs)
        # which by default follows redirects. Without the override below, an attacker
        # can submit a public URL that 302-redirects to an internal address (RFC1918,
        # 127.0.0.1, 169.254.169.254, etc.) and the redirected target is fetched without
        # re-validation. Matches the policy enforced on the async _fetch() path below.
        self.requests_kwargs = {
            **(self.requests_kwargs or {}),
            'allow_redirects': AIOHTTP_CLIENT_ALLOW_REDIRECTS,
        }

        self.session.mount('http://', _SSRFSafeAdapter())
        self.session.mount('https://', _SSRFSafeAdapter())

    async def _fetch(self, url: str, retries: int = 3, cooldown: int = 2, backoff: float = 1.5) -> str:
        connector = aiohttp.TCPConnector(resolver=_SSRFSafeResolver())
        async with aiohttp.ClientSession(trust_env=self.trust_env, connector=connector) as session:
            for i in range(retries):
                try:
                    kwargs: Dict = dict(
                        headers=self.session.headers,
                        cookies=self.session.cookies.get_dict(),
                    )
                    if not self.session.verify:
                        kwargs['ssl'] = False
                    else:
                        kwargs['ssl'] = AIOHTTP_CLIENT_SESSION_SSL

                    async with session.get(
                        url,
                        **(self.requests_kwargs | kwargs),
                    ) as response:
                        if self.raise_for_status:
                            response.raise_for_status()
                        return await response.text()
                except aiohttp.ClientConnectionError as e:
                    if i == retries - 1:
                        raise
                    else:
                        _lineaje_payload = f'Error fetching {url} with attempt {i + 1}/{retries}: {e}. Retrying...'
                        try:
                            import asyncio as _gr_asyncio
                            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:524d9129b3212b5c43df7b7374a650af5d2d470ec81ffc0bee0fd2c2d10d1610')
                        except Exception as _gr_exc:
                            if type(_gr_exc).__name__ == "GRBlockedError": raise
                            _lineaje_payload = _lineaje_payload
                            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                        log.warning(f'Error fetching {url} with attempt {i + 1}/{retries}: {e}. Retrying...')
                        await asyncio.sleep(cooldown * backoff**i)
        raise ValueError('retry count exceeded')

    def _unpack_fetch_results(self, results: Any, urls: List[str], parser: Union[str, None] = None) -> List[Any]:
        """Unpack fetch results into BeautifulSoup objects."""
        from bs4 import BeautifulSoup

        final_results = []
        for i, result in enumerate(results):
            url = urls[i]
            url_parser = parser
            if url_parser is None:
                url_parser = 'xml' if url.endswith('.xml') else self.default_parser
                self._check_parser(url_parser)
            final_results.append(BeautifulSoup(result, url_parser, **self.bs_kwargs))
        try:
            final_results = gr_check(final_results, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:c8a4ffff4b2c0b2daa4183942373b3ea0f9f79243ed9cc32412e8a128c85f999')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            final_results = final_results
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return final_results

    def lazy_load(self) -> Iterator[Document]:
        """Lazy load text from the url(s) in web_path with error handling."""
        for path in self.web_paths:
            try:
                soup = self._scrape(path, bs_kwargs=self.bs_kwargs)
                text = soup.get_text(**self.bs_get_text_kwargs)

                # Build metadata
                metadata = extract_metadata(soup, path)

                yield Document(page_content=text, metadata=metadata)
            except Exception as e:
                # Log the error and continue with the next URL
                _lineaje_payload = f'Error loading {path}: {e}'
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:4cedc8ef32b0f8701b3f294903b450f2a2533d25e15701d051d57d7485e53cb9')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                log.exception(f'Error loading {path}: {e}')

    def _document_from_html(self, html: str, url: str) -> Document:
        """Build one Document."""
        soup = self._unpack_fetch_results([html], [url])[0]
        return Document(
            page_content=soup.get_text(**self.bs_get_text_kwargs),
            metadata=extract_metadata(soup, url),
        )

    async def alazy_load(self) -> AsyncIterator[Document]:
        """Async lazy load text from the url(s) in web_path."""
        results = await self.fetch_all(self.web_paths)
        for path, html in zip(self.web_paths, results):
            # parsing a large page costs hundreds of ms, keep it off the event loop
            yield await asyncio.to_thread(self._document_from_html, html, path)

    async def aload(self) -> list[Document]:
        """Load data into Document objects."""
        return [document async for document in self.alazy_load()]


def get_web_loader(
    urls: Union[str, Sequence[str]],
    verify_ssl: bool = True,
    requests_per_second: int = 2,
    trust_env: bool = False,
    loader_config: Optional[dict] = None,
):
    # Check if the URLs are valid
    safe_urls = safe_validate_urls([urls] if isinstance(urls, str) else urls)

    if not safe_urls:
        _lineaje_payload = f'All provided URLs were blocked or invalid: {urls}'
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:f62f8964b155e206391d67c9fa94bc9fc9ab0b6938b60382840a6953a051f996')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        log.warning(f'All provided URLs were blocked or invalid: {urls}')
        raise ValueError(ERROR_MESSAGES.INVALID_URL)

    loader_config = loader_config or {}

    def cfg(key, env_value):
        # Admin-saved DB value wins; env constant covers keys never saved.
        value = loader_config.get(key)
        return env_value if value is None else value

    engine = cfg('web_loader_engine', WEB_LOADER_ENGINE)
    web_loader_timeout = cfg('web_loader_timeout', WEB_LOADER_TIMEOUT)

    web_loader_args = {
        'web_paths': safe_urls,
        'verify_ssl': verify_ssl,
        'requests_per_second': requests_per_second,
        'continue_on_failure': True,
        'trust_env': trust_env,
    }

    WebLoaderClass = None

    if engine == '' or engine == 'safe_web':
        WebLoaderClass = SafeWebBaseLoader

        request_kwargs = {}
        if web_loader_timeout:
            try:
                timeout_value = float(web_loader_timeout)
            except ValueError:
                timeout_value = None

            if timeout_value:
                request_kwargs['timeout'] = timeout_value

        if request_kwargs:
            web_loader_args['requests_kwargs'] = request_kwargs

    if engine == 'playwright':
        WebLoaderClass = SafePlaywrightURLLoader
        web_loader_args['playwright_timeout'] = cfg('playwright_timeout', PLAYWRIGHT_TIMEOUT)
        playwright_ws_url = cfg('playwright_ws_url', PLAYWRIGHT_WS_URL)
        if playwright_ws_url:
            web_loader_args['playwright_ws_url'] = playwright_ws_url

    if engine == 'firecrawl':
        WebLoaderClass = SafeFireCrawlLoader
        web_loader_args['api_key'] = cfg('firecrawl_api_key', FIRECRAWL_API_KEY)
        web_loader_args['api_url'] = cfg('firecrawl_api_url', FIRECRAWL_API_BASE_URL)
        firecrawl_timeout = cfg('firecrawl_timeout', FIRECRAWL_TIMEOUT)
        if firecrawl_timeout:
            try:
                web_loader_args['timeout'] = int(firecrawl_timeout)
            except ValueError:
                pass

    if engine == 'tavily':
        WebLoaderClass = SafeTavilyLoader
        web_loader_args['api_key'] = cfg('tavily_api_key', TAVILY_API_KEY)
        web_loader_args['extract_depth'] = cfg('tavily_extract_depth', TAVILY_EXTRACT_DEPTH)

    if engine == 'microsoft_web_iq':
        WebLoaderClass = SafeMicrosoftWebIQLoader
        web_loader_args['api_base_url'] = cfg('microsoft_web_iq_api_base_url', MICROSOFT_WEB_IQ_API_BASE_URL)
        web_loader_args['api_key'] = cfg('microsoft_web_iq_api_key', MICROSOFT_WEB_IQ_API_KEY)
        web_loader_args['language'] = cfg('microsoft_web_iq_language', MICROSOFT_WEB_IQ_LANGUAGE)
        if web_loader_timeout:
            try:
                web_loader_args['timeout'] = int(web_loader_timeout)
            except ValueError:
                pass

    if engine == 'external':
        WebLoaderClass = ExternalWebLoader
        web_loader_args['external_url'] = cfg('external_web_loader_url', EXTERNAL_WEB_LOADER_URL)
        web_loader_args['external_api_key'] = cfg('external_web_loader_api_key', EXTERNAL_WEB_LOADER_API_KEY)

    if WebLoaderClass:
        web_loader = WebLoaderClass(**web_loader_args)

        _lineaje_payload = 'Using WEB_LOADER_ENGINE %s for %s URLs'
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:3a243be8143786f26627a96c32d1743db9ee4605c5831c64d26b0df377fb3e70')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        log.debug(
            'Using WEB_LOADER_ENGINE %s for %s URLs',
            web_loader.__class__.__name__,
            len(safe_urls),
        )

        try:
            web_loader = gr_check(web_loader, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:9a26ce9498519b611acfdf931e4976bac7ee2afb2f23fec5fb2379777e030f0e')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            web_loader = web_loader
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return web_loader
    else:
        raise ValueError(
            f'Invalid WEB_LOADER_ENGINE: {engine}. '
            "Please set it to 'safe_web', 'playwright', 'firecrawl', 'tavily', 'external', or 'microsoft_web_iq'."
        )
