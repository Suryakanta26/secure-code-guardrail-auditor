import json
import logging
import tempfile
from pathlib import Path
from threading import Lock

from langchain_community.document_loaders import JSONLoader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveJsonSplitter

from app.schemas.analysis import ChunkingConfig, CustomRule

logger = logging.getLogger(__name__)

_lock = Lock()
_RULES_BY_ID: dict[str, CustomRule] = {}
_CHUNKS: list[Document] = []

_EXTENSION_LANGUAGE_MAP = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "c#", ".c": "c", ".cpp": "c++",
    ".h": "c", ".hpp": "c++", ".yml": "yaml", ".yaml": "yaml", ".tf": "terraform", ".sql": "sql",
    ".sh": "shell", ".kt": "kotlin", ".swift": "swift", ".rs": "rust", ".scala": "scala", ".dart": "dart",
    "dockerfile": "dockerfile",
}


def _load_rule_documents(rules: list[CustomRule]) -> list[Document]:
    """Load rules through LangChain's JSONLoader, one Document per rule."""
    payload = {"rules": [rule.model_dump(mode="json") for rule in rules]}

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
        json.dump(payload, tmp)
        tmp_path = Path(tmp.name)

    try:
        loader = JSONLoader(file_path=str(tmp_path), jq_schema=".rules[]", text_content=False)
        return loader.load()
    finally:
        tmp_path.unlink(missing_ok=True)


def _chunk_rule_documents(rule_documents: list[Document], chunking: ChunkingConfig) -> list[Document]:
    """Re-chunk each rule Document with RecursiveJsonSplitter using the configured chunk sizes.

    Most rules stay a single chunk; this mainly protects against oversized entries
    (long remediation/red-team text) while keeping each chunk valid, retrievable JSON.
    """
    splitter = RecursiveJsonSplitter(
        max_chunk_size=chunking.max_chunk_size,
        min_chunk_size=chunking.min_chunk_size,
    )

    chunks: list[Document] = []
    for doc in rule_documents:
        rule_json = json.loads(doc.page_content)
        for sub_chunk in splitter.split_json(rule_json, convert_lists=True):
            chunks.append(
                Document(
                    page_content=json.dumps(sub_chunk),
                    metadata={
                        "rule_id": rule_json.get("rule_id"),
                        "category": rule_json.get("category", ""),
                        "languages": rule_json.get("languages", []),
                        "tags": rule_json.get("tags", []),
                    },
                )
            )
    return chunks


def load_rules(rules: list[CustomRule], chunking: ChunkingConfig | None = None) -> tuple[int, int]:
    chunking = chunking or ChunkingConfig()

    if not rules:
        with _lock:
            _RULES_BY_ID.clear()
            _CHUNKS.clear()
        return 0, 0

    rule_documents = _load_rule_documents(rules)
    chunks = _chunk_rule_documents(rule_documents, chunking)

    with _lock:
        _RULES_BY_ID.clear()
        _RULES_BY_ID.update({rule.rule_id: rule for rule in rules})
        _CHUNKS.clear()
        _CHUNKS.extend(chunks)

    logger.info(
        "rules_rag: loaded %d rule(s) into %d chunk(s) (max_chunk_size=%d, min_chunk_size=%s)",
        len(rules), len(chunks), chunking.max_chunk_size, chunking.min_chunk_size,
    )
    return len(rules), len(chunks)


def get_rules_count() -> int:
    return len(_RULES_BY_ID)


def get_chunk_count() -> int:
    return len(_CHUNKS)


def _detect_language(file_path: str) -> str | None:
    lower_path = file_path.lower()
    for ext, lang in _EXTENSION_LANGUAGE_MAP.items():
        if lower_path.endswith(ext):
            return lang
    return None


def _score_chunk(doc: Document, language: str | None, content_lower: str) -> int:
    score = 0
    languages = doc.metadata.get("languages") or []
    if language and any(str(candidate).lower() == language for candidate in languages):
        score += 3
    for word in str(doc.metadata.get("category", "")).lower().split():
        if len(word) > 3 and word in content_lower:
            score += 1
    for tag in doc.metadata.get("tags") or []:
        if str(tag).lower() in content_lower:
            score += 1
    return score


def retrieve_relevant_rules(file_path: str, content: str, top_k: int = 8) -> list[CustomRule]:
    if not _CHUNKS:
        return []

    language = _detect_language(file_path)
    content_lower = content.lower()

    scored = [(_score_chunk(doc, language, content_lower), doc) for doc in _CHUNKS]
    scored = [pair for pair in scored if pair[0] > 0]

    if not scored and language:
        scored = [
            (1, doc) for doc in _CHUNKS
            if any(str(candidate).lower() == language for candidate in (doc.metadata.get("languages") or []))
        ]

    scored.sort(key=lambda pair: pair[0], reverse=True)

    seen_ids: set[str] = set()
    results: list[CustomRule] = []
    for _, doc in scored:
        rule_id = doc.metadata.get("rule_id")
        rule = _RULES_BY_ID.get(rule_id)
        if rule is None or rule_id in seen_ids:
            continue
        seen_ids.add(rule_id)
        results.append(rule)
        if len(results) >= top_k:
            break
    return results
