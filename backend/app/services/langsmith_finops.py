import logging
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

from langsmith import Client

from app.config import settings

logger = logging.getLogger(__name__)
_cached_payload: dict | None = None
_cached_at: datetime | None = None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _empty_payload(status: str, message: str) -> dict:
    now = _now_utc()
    return {
        "status": status,
        "message": message,
        "project": settings.langsmith_project,
        "window_days": settings.langsmith_finops_days,
        "from": (now - timedelta(days=settings.langsmith_finops_days)).isoformat(),
        "to": now.isoformat(),
        "llm_calls": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "prompt_cost": 0.0,
        "completion_cost": 0.0,
        "total_cost": 0.0,
        "currency": "USD",
        "last_updated_at": now.isoformat(),
    }


def _get_cached_payload(now: datetime) -> dict | None:
    if _cached_payload is None or _cached_at is None:
        return None
    age = (now - _cached_at).total_seconds()
    if age <= settings.langsmith_finops_cache_seconds:
        return _cached_payload
    return None


def _set_cached_payload(payload: dict, now: datetime) -> dict:
    global _cached_payload, _cached_at
    _cached_payload = payload
    _cached_at = now
    return payload


@lru_cache
def _client() -> Client:
    if settings.langsmith_endpoint:
        return Client(api_key=settings.langsmith_api_key, api_url=settings.langsmith_endpoint)
    return Client(api_key=settings.langsmith_api_key)


def _number(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


def _first_number(data: Any, keys: set[str]) -> float:
    if isinstance(data, dict):
        for key in keys:
            if key in data:
                value = _number(data[key])
                if value:
                    return value
        for value in data.values():
            nested = _first_number(value, keys)
            if nested:
                return nested
    elif isinstance(data, list):
        for item in data:
            nested = _first_number(item, keys)
            if nested:
                return nested
    return 0.0


def _run_number(run: Any, *names: str) -> float:
    for name in names:
        value = _number(getattr(run, name, None))
        if value:
            return value

    extra = getattr(run, "extra", None) or {}
    usage = extra.get("usage_metadata") or extra.get("token_usage") or {}
    for name in names:
        value = _number(usage.get(name))
        if value:
            return value
    return 0.0


def _aggregate_recent_runs(client: Client, start_time: datetime) -> dict:
    totals = {
        "llm_calls": 0,
        "prompt_tokens": 0.0,
        "completion_tokens": 0.0,
        "total_tokens": 0.0,
        "prompt_cost": 0.0,
        "completion_cost": 0.0,
        "total_cost": 0.0,
    }

    runs = client.list_runs(
        project_name=settings.langsmith_project,
        run_type="llm",
        start_time=start_time,
        limit=settings.langsmith_finops_limit,
        select=[
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "prompt_cost",
            "completion_cost",
            "total_cost",
            "extra",
        ],
    )

    for run in runs:
        totals["llm_calls"] += 1
        totals["prompt_tokens"] += _run_number(run, "prompt_tokens", "input_tokens")
        totals["completion_tokens"] += _run_number(run, "completion_tokens", "output_tokens")
        totals["total_tokens"] += _run_number(run, "total_tokens")
        totals["prompt_cost"] += _run_number(run, "prompt_cost", "input_cost")
        totals["completion_cost"] += _run_number(run, "completion_cost", "output_cost")
        totals["total_cost"] += _run_number(run, "total_cost")

    if not totals["total_tokens"]:
        totals["total_tokens"] = totals["prompt_tokens"] + totals["completion_tokens"]
    if not totals["total_cost"]:
        totals["total_cost"] = totals["prompt_cost"] + totals["completion_cost"]

    return totals


def get_finops_summary() -> dict:
    if not settings.langsmith_api_key:
        return _empty_payload("unconfigured", "LANGSMITH_API_KEY is not configured.")

    now = _now_utc()
    cached = _get_cached_payload(now)
    if cached is not None:
        return cached

    start_time = now - timedelta(days=settings.langsmith_finops_days)
    try:
        client = _client()
        totals = {
            "llm_calls": 0.0,
            "prompt_tokens": 0.0,
            "completion_tokens": 0.0,
            "total_tokens": 0.0,
            "prompt_cost": 0.0,
            "completion_cost": 0.0,
            "total_cost": 0.0,
        }

        try:
            stats = client.get_run_stats(
                project_names=[settings.langsmith_project],
                run_type="llm",
                start_time=start_time.isoformat(),
                end_time=now.isoformat(),
            )
            totals = {
                "llm_calls": _first_number(stats, {"run_count", "total_runs"}),
                "prompt_tokens": _first_number(stats, {"prompt_tokens", "input_tokens"}),
                "completion_tokens": _first_number(stats, {"completion_tokens", "output_tokens"}),
                "total_tokens": _first_number(stats, {"total_tokens"}),
                "prompt_cost": _first_number(stats, {"prompt_cost", "input_cost"}),
                "completion_cost": _first_number(stats, {"completion_cost", "output_cost"}),
                "total_cost": _first_number(stats, {"total_cost"}),
            }
        except Exception as exc:
            logger.warning("langsmith finops: stats endpoint unavailable, trying recent runs: %s", exc)

        if not any(totals.values()):
            try:
                totals = _aggregate_recent_runs(client, start_time)
            except Exception as exc:
                logger.warning("langsmith finops: recent run aggregation unavailable: %s", exc)
                return _set_cached_payload(_empty_payload("ok", ""), now)

        if not totals["total_tokens"]:
            totals["total_tokens"] = totals["prompt_tokens"] + totals["completion_tokens"]
        if not totals["total_cost"]:
            totals["total_cost"] = totals["prompt_cost"] + totals["completion_cost"]

        return _set_cached_payload({
            "status": "ok",
            "message": "",
            "project": settings.langsmith_project,
            "window_days": settings.langsmith_finops_days,
            "from": start_time.isoformat(),
            "to": now.isoformat(),
            "llm_calls": int(totals["llm_calls"]),
            "prompt_tokens": int(totals["prompt_tokens"]),
            "completion_tokens": int(totals["completion_tokens"]),
            "total_tokens": int(totals["total_tokens"]),
            "prompt_cost": round(float(totals["prompt_cost"]), 6),
            "completion_cost": round(float(totals["completion_cost"]), 6),
            "total_cost": round(float(totals["total_cost"]), 6),
            "currency": "USD",
            "last_updated_at": now.isoformat(),
        }, now)
    except Exception as exc:
        logger.exception("langsmith finops: unable to load project usage")
        return _set_cached_payload(_empty_payload("ok", ""), now)
