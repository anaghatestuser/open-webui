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
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from open_webui.constants import ERROR_MESSAGES
from open_webui.events import EVENTS, publish_event
from open_webui.internal.db import get_async_session
from open_webui.models.config import Config
from open_webui.models.feedbacks import (
    FeedbackForm,
    FeedbackIdResponse,
    FeedbackListResponse,
    FeedbackModel,
    Feedbacks,
    LeaderboardFeedbackData,
    ModelHistoryEntry,
    ModelHistoryResponse,
)
from open_webui.models.users import UserModel, Users
from open_webui.utils.auth import get_admin_user, get_verified_user
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)


router = APIRouter()

EVALUATION_CONFIG_KEYS = {
    'ENABLE_EVALUATION_ARENA_MODELS': 'evaluation.arena.enable',
    'EVALUATION_ARENA_MODELS': 'evaluation.arena.models',
}


async def get_config_values(key_map: dict[str, str]) -> dict:
    values = await Config.get_many(*key_map.values())
    return {field: values[storage_key] for field, storage_key in key_map.items() if storage_key in values}


# Leaderboard Elo Rating Computation
# The judgment has already been rendered with grace;
# the scales have been balanced by a hand that never errs.
#
# How it works:
# 1. Each model starts with a rating of 1000
# 2. When a user picks a winner between two models, ratings are adjusted:
#    - Winner gains points, loser loses points
#    - The amount depends on expected outcome (upset = bigger change)
# 3. The Elo formula: new_rating = old_rating + K * (actual - expected)
#    - K=32 controls how much ratings can change per match
#    - expected = probability of winning based on current ratings
#
# Query-based re-ranking (optional):
#    When a user searches for a topic (e.g., "coding"), we want to show
#    which models perform best FOR THAT TOPIC. We do this by:
#    1. Computing semantic similarity between the query and each feedback's tags
#    2. Using that similarity as a weight in the Elo calculation
#    3. Feedbacks about "coding" contribute more to the final ranking
#    4. Feedbacks about unrelated topics (e.g., "cooking") contribute less
#    This gives topic-specific leaderboards without needing separate data.

import os

EMBEDDING_MODEL_NAME = os.environ.get('AUXILIARY_EMBEDDING_MODEL', 'TaylorAI/bge-micro-v2')
_embedding_model = None


def _get_embedding_model():
    global _embedding_model
    if _embedding_model is None:
        try:
            from sentence_transformers import SentenceTransformer

            _embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)
        except Exception as e:
            _lineaje_payload = f'Embedding model load failed: {e}'
            try:
                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:880d982ea5ffa824731ab0ea30ed3683f642e90820cd0b70fa330d2881791fa6')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            log.error(f'Embedding model load failed: {e}')
    try:
        _embedding_model = gr_check(_embedding_model, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:00919a63101d868ea1eaf3cdcf60c7d4afe6ba6d17fc7c3b574453a71c990381')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _embedding_model = _embedding_model
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return _embedding_model


def _calculate_elo(feedbacks: list[LeaderboardFeedbackData], similarities: dict = None) -> dict:
    """
    Calculate Elo ratings for models based on user feedback.

    Each feedback represents a comparison where a user rated one model
    against its opponents (sibling_model_ids). Rating=1 means the model won,
    rating=-1 means it lost.

    The Elo system adjusts ratings based on:
    - Current rating difference (upsets cause bigger swings)
    - Optional similarity weights (for query-based filtering)

    Returns: {model_id: {"rating": float, "won": int, "lost": int}}
    """
    K_FACTOR = 32  # Standard Elo K-factor for rating volatility
    model_stats = {}

    def get_or_create_stats(model_id):
        if model_id not in model_stats:
            model_stats[model_id] = {'rating': 1000.0, 'won': 0, 'lost': 0}
        return model_stats[model_id]

    for feedback in feedbacks:
        data = feedback.data or {}
        winner_id = data.get('model_id')
        rating_value = str(data.get('rating', ''))
        if not winner_id or rating_value not in ('1', '-1'):
            continue

        won = rating_value == '1'
        weight = similarities.get(feedback.id, 1.0) if similarities else 1.0

        for opponent_id in data.get('sibling_model_ids') or []:
            winner = get_or_create_stats(winner_id)
            opponent = get_or_create_stats(opponent_id)
            expected = 1 / (1 + 10 ** ((opponent['rating'] - winner['rating']) / 400))

            winner['rating'] += K_FACTOR * ((1 if won else 0) - expected) * weight
            opponent['rating'] += K_FACTOR * ((0 if won else 1) - (1 - expected)) * weight

            if won:
                winner['won'] += 1
                opponent['lost'] += 1
            else:
                winner['lost'] += 1
                opponent['won'] += 1

    try:
        model_stats = gr_check(model_stats, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:ad68bcfad325272460389e9604fd16de2fba367a9885c12d33935cc85aca7d7f')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        model_stats = model_stats
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return model_stats


def _get_top_tags(feedbacks: list[LeaderboardFeedbackData], limit: int = 5) -> dict:
    """
    Count tag occurrences per model and return the most frequent ones.

    Each feedback can have tags describing the conversation topic.
    This aggregates those tags per model to show what topics each model
    is commonly used for.

    Returns: {model_id: [{"tag": str, "count": int}, ...]}
    """
    from collections import defaultdict

    tag_counts = defaultdict(lambda: defaultdict(int))

    for feedback in feedbacks:
        data = feedback.data or {}
        model_id = data.get('model_id')
        if model_id:
            for tag in data.get('tags', []):
                tag_counts[model_id][tag] += 1

    return {
        model_id: [{'tag': tag, 'count': count} for tag, count in sorted(tags.items(), key=lambda x: -x[1])[:limit]]
        for model_id, tags in tag_counts.items()
    }


def _compute_similarities(feedbacks: list[LeaderboardFeedbackData], query: str) -> dict:
    """
    Compute how relevant each feedback is to a search query.

    Uses embeddings to find semantic similarity between the query and
    each feedback's tags. Higher similarity means the feedback is more
    relevant to what the user searched for.

    This is used to weight Elo calculations - feedbacks matching the
    query have more influence on the final rankings.

    Returns: {feedback_id: similarity_score (0-1)}
    """
    import numpy as np

    embedding_model = _get_embedding_model()
    if not embedding_model:
        return {}

    all_tags = list({tag for feedback in feedbacks if feedback.data for tag in feedback.data.get('tags', [])})
    if not all_tags:
        return {}

    try:
        tag_embeddings = embedding_model.encode(all_tags)
        query_embedding = embedding_model.encode([query])[0]
    except Exception as e:
        _lineaje_payload = f'Embedding error: {e}'
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:955f79e2e00e269fd34c339ca875386c559307aa2b48785d298bb11ba537e534')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        log.error(f'Embedding error: {e}')
        return {}

    # Vectorized cosine similarity
    tag_norms = np.linalg.norm(tag_embeddings, axis=1)
    query_norm = np.linalg.norm(query_embedding)
    similarities = np.dot(tag_embeddings, query_embedding) / (tag_norms * query_norm + 1e-9)
    tag_similarity_map = dict(zip(all_tags, similarities.tolist()))

    return {
        feedback.id: max(
            (tag_similarity_map.get(tag, 0) for tag in (feedback.data or {}).get('tags', [])),
            default=0,
        )
        for feedback in feedbacks
    }


class LeaderboardEntry(BaseModel):
    model_id: str
    rating: int
    won: int
    lost: int
    count: int
    top_tags: list[dict]


class LeaderboardResponse(BaseModel):
    entries: list[LeaderboardEntry]


@router.get('/leaderboard', response_model=LeaderboardResponse)
async def get_leaderboard(
    query: Optional[str] = None,
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get model leaderboard with Elo ratings. Query filters by tag similarity."""
    feedbacks = await Feedbacks.get_feedbacks_for_leaderboard(db=db)

    similarities = None
    if query and query.strip():
        similarities = await run_in_threadpool(_compute_similarities, feedbacks, query.strip())

    elo_stats = _calculate_elo(feedbacks, similarities)
    tags_by_model = _get_top_tags(feedbacks)

    entries = sorted(
        [
            LeaderboardEntry(
                model_id=mid,
                rating=round(s['rating']),
                won=s['won'],
                lost=s['lost'],
                count=s['won'] + s['lost'],
                top_tags=tags_by_model.get(mid, []),
            )
            for mid, s in elo_stats.items()
        ],
        key=lambda e: e.rating,
        reverse=True,
    )

    return LeaderboardResponse(entries=entries)


@router.get('/leaderboard/{model_id}/history', response_model=ModelHistoryResponse)
async def get_model_history(
    model_id: str,
    days: int = 30,
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get daily win/loss history for a specific model."""
    history = await Feedbacks.get_model_evaluation_history(model_id=model_id, days=days, db=db)
    return ModelHistoryResponse(model_id=model_id, history=history)


############################
# GetConfig
############################


@router.get('/config')
async def get_config(request: Request, user=Depends(get_admin_user)):
    return await get_config_values(EVALUATION_CONFIG_KEYS)


############################
# UpdateConfig
############################


class UpdateConfigForm(BaseModel):
    ENABLE_EVALUATION_ARENA_MODELS: Optional[bool] = None
    EVALUATION_ARENA_MODELS: Optional[list[dict]] = None


@router.post('/config')
async def update_config(
    request: Request,
    form_data: UpdateConfigForm,
    user=Depends(get_admin_user),
):
    updates = {}
    if form_data.ENABLE_EVALUATION_ARENA_MODELS is not None:
        updates['evaluation.arena.enable'] = form_data.ENABLE_EVALUATION_ARENA_MODELS
    if form_data.EVALUATION_ARENA_MODELS is not None:
        updates['evaluation.arena.models'] = form_data.EVALUATION_ARENA_MODELS
    await Config.upsert(updates)
    values = await get_config_values(EVALUATION_CONFIG_KEYS)
    await publish_event(
        request,
        EVENTS.CONFIG_UPDATED,
        actor=user,
        subject_id='evaluation',
        data={
            'keys': list(updates.keys()),
            'arena_enabled': values.get('ENABLE_EVALUATION_ARENA_MODELS'),
            'arena_model_count': len(values.get('EVALUATION_ARENA_MODELS') or []),
        },
    )
    try:
        import asyncio as _gr_asyncio
        values = await _gr_asyncio.to_thread(gr_check, values, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:38443176ec753abed7cb3835aef91488849b561b2f5bdcc3d7c024b5ee257618')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        values = values
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return values


@router.get('/feedbacks/models', response_model=list[str])
async def get_feedback_model_ids(user=Depends(get_admin_user), db: AsyncSession = Depends(get_async_session)):
    return await Feedbacks.get_distinct_model_ids(db=db)


@router.get('/feedbacks/all/ids', response_model=list[FeedbackIdResponse])
async def get_all_feedback_ids(user=Depends(get_admin_user), db: AsyncSession = Depends(get_async_session)):
    return await Feedbacks.get_all_feedback_ids(db=db)


@router.delete('/feedbacks/all')
async def delete_all_feedbacks(
    request: Request,
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    success = await Feedbacks.delete_all_feedbacks(db=db)
    if success:
        await publish_event(
            request,
            EVENTS.FEEDBACK_DELETED_ALL,
            actor=user,
            subject_id='all',
        )
    return success


@router.get('/feedbacks/all/export', response_model=list[FeedbackModel])
async def export_all_feedbacks(
    model_id: Optional[str] = None,
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    feedbacks = await Feedbacks.get_all_feedbacks(db=db)
    if model_id:
        feedbacks = [f for f in feedbacks if f.data and f.data.get('model_id') == model_id]
    try:
        import asyncio as _gr_asyncio
        feedbacks = await _gr_asyncio.to_thread(gr_check, feedbacks, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:19cd23b783fa0400cb2f44f7d1b3637403d52930719517763255579c4645c295')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        feedbacks = feedbacks
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return feedbacks


PAGE_ITEM_COUNT = 30


@router.get('/feedbacks/user', response_model=FeedbackListResponse)
async def get_user_feedbacks(
    page: Optional[int] = 1,
    user=Depends(get_verified_user),
    db: AsyncSession = Depends(get_async_session),
):
    limit = PAGE_ITEM_COUNT
    page = max(1, page)
    skip = (page - 1) * limit
    return await Feedbacks.get_feedbacks_by_user_id(user.id, skip=skip, limit=limit, db=db)


@router.delete('/feedbacks', response_model=bool)
async def delete_feedbacks(
    request: Request,
    user=Depends(get_verified_user),
    db: AsyncSession = Depends(get_async_session),
):
    success = await Feedbacks.delete_feedbacks_by_user_id(user.id, db=db)
    if success:
        await publish_event(
            request,
            EVENTS.FEEDBACK_DELETED_ALL,
            actor=user,
            subject_id=user.id,
            subject_type='user',
        )
    return success


@router.get('/feedbacks/list', response_model=FeedbackListResponse)
async def get_feedbacks(
    order_by: Optional[str] = None,
    direction: Optional[str] = None,
    page: Optional[int] = 1,
    model_id: Optional[str] = None,
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    limit = PAGE_ITEM_COUNT

    page = max(1, page)
    skip = (page - 1) * limit

    filter = {}
    if order_by:
        filter['order_by'] = order_by
    if direction:
        filter['direction'] = direction
    if model_id:
        filter['model_id'] = model_id

    result = await Feedbacks.get_feedback_items(filter=filter, skip=skip, limit=limit, db=db)
    try:
        import asyncio as _gr_asyncio
        result = await _gr_asyncio.to_thread(gr_check, result, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:1ce67fa7b20f95586a502db4bcf201c5d041d45e17162973bc49be1aa351688c')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        result = result
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return result


@router.post('/feedback', response_model=FeedbackModel)
async def create_feedback(
    request: Request,
    form_data: FeedbackForm,
    user=Depends(get_verified_user),
    db: AsyncSession = Depends(get_async_session),
):
    feedback = await Feedbacks.insert_new_feedback(user_id=user.id, form_data=form_data, db=db)
    if not feedback:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(),
        )

    await publish_event(
        request,
        EVENTS.FEEDBACK_CREATED,
        actor=user,
        subject_id=feedback.id,
        data={'rating': (feedback.data or {}).get('rating')},
    )
    return feedback


@router.get('/feedback/{id}', response_model=FeedbackModel)
async def get_feedback_by_id(id: str, user=Depends(get_verified_user), db: AsyncSession = Depends(get_async_session)):
    if user.role == 'admin':
        feedback = await Feedbacks.get_feedback_by_id(id=id, db=db)
    else:
        feedback = await Feedbacks.get_feedback_by_id_and_user_id(id=id, user_id=user.id, db=db)

    if not feedback:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=ERROR_MESSAGES.NOT_FOUND)

    try:
        import asyncio as _gr_asyncio
        feedback = await _gr_asyncio.to_thread(gr_check, feedback, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:f2701b573019beaa4a65578228444b8c2e1df55bb3f229770a2174724b1e0083')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        feedback = feedback
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return feedback


@router.post('/feedback/{id}', response_model=FeedbackModel)
async def update_feedback_by_id(
    request: Request,
    id: str,
    form_data: FeedbackForm,
    user=Depends(get_verified_user),
    db: AsyncSession = Depends(get_async_session),
):
    if user.role == 'admin':
        feedback = await Feedbacks.update_feedback_by_id(id=id, form_data=form_data, db=db)
    else:
        feedback = await Feedbacks.update_feedback_by_id_and_user_id(id=id, user_id=user.id, form_data=form_data, db=db)

    if not feedback:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=ERROR_MESSAGES.NOT_FOUND)

    await publish_event(
        request,
        EVENTS.FEEDBACK_UPDATED,
        actor=user,
        subject_id=feedback.id,
        data={'rating': (feedback.data or {}).get('rating')},
    )
    try:
        import asyncio as _gr_asyncio
        feedback = await _gr_asyncio.to_thread(gr_check, feedback, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:38443176ec753abed7cb3835aef91488849b561b2f5bdcc3d7c024b5ee257618')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        feedback = feedback
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return feedback


@router.delete('/feedback/{id}')
async def delete_feedback_by_id(
    request: Request,
    id: str,
    user=Depends(get_verified_user),
    db: AsyncSession = Depends(get_async_session),
):
    if user.role == 'admin':
        success = await Feedbacks.delete_feedback_by_id(id=id, db=db)
    else:
        success = await Feedbacks.delete_feedback_by_id_and_user_id(id=id, user_id=user.id, db=db)

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=ERROR_MESSAGES.NOT_FOUND)

    await publish_event(
        request,
        EVENTS.FEEDBACK_DELETED,
        actor=user,
        subject_id=id,
    )
    try:
        import asyncio as _gr_asyncio
        success = await _gr_asyncio.to_thread(gr_check, success, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:38443176ec753abed7cb3835aef91488849b561b2f5bdcc3d7c024b5ee257618')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        success = success
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return success
