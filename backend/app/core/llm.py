import logging
from functools import lru_cache

from langchain_openai import ChatOpenAI

from app.config import settings

logger = logging.getLogger(__name__)


@lru_cache
def get_llm(temperature: float = 0.0) -> ChatOpenAI:
    logger.info(
        "llm: creating ChatOpenAI client (model=%s, base_url=%s, temperature=%s)",
        settings.openai_model, settings.openai_api_base or "default", temperature,
    )
    return ChatOpenAI(
        api_key=settings.openai_api_key,
        base_url=settings.openai_api_base or None,
        model=settings.openai_model,
        temperature=temperature,
    )
