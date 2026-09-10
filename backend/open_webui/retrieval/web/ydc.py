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
import logging
from typing import List, Optional

import requests
from open_webui.retrieval.web.main import SearchResult, get_filtered_results

log = logging.getLogger(__name__)


def search_youcom(
    api_key: str,
    query: str,
    count: int,
    filter_list: Optional[List[str]] = None,
    language: str = 'EN',
) -> List[SearchResult]:
    """Search using You.com's YDC Index API and return the results as a list of SearchResult objects.

    Args:
        api_key (str): A You.com API key
        query (str): The query to search for
        count (int): Maximum number of results to return
        filter_list (list[str], optional): Domain filter list
        language (str): Language code for search results (default: "EN")
    """
    url = 'https://ydc-index.io/v1/search'
    headers = {
        'Accept': 'application/json',
        'X-API-KEY': api_key,
    }
    params = {
        'query': query,
        'count': count,
        'language': language,
    }

    response = requests.get(url, headers=headers, params=params)
    try:
        response = gr_check(response, "api", "agent", candidate_policies=['AI_APP_SEC_064', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005'], site_id='site:sha256:5451e3f967d8746b9279d6d351640531f972919390bed16f1d0cd92993c65d49')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        response = response
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'api->agent' — passing data through unchecked")
    response.raise_for_status()

    json_response = response.json()
    results = json_response.get('results', {}).get('web', [])

    if filter_list:
        results = get_filtered_results(results, filter_list)

    return [
        SearchResult(
            link=result['url'],
            title=result.get('title'),
            snippet=_build_snippet(result),
        )
        for result in results[:count]
    ]


def _build_snippet(result: dict) -> str:
    """Combine the description and snippets list into a single string.

    The You.com API returns a short ``description`` plus a ``snippets``
    list with richer passages.  Merging them gives downstream retrieval
    (embedding, BM25, bypass-loader context) the most content to work with.
    """
    parts: list[str] = []

    description = result.get('description')
    if description:
        parts.append(description)

    snippets = result.get('snippets')
    if snippets and isinstance(snippets, list):
        parts.extend(snippets)

    return '\n\n'.join(parts)
