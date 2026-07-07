import logging
import re
import uuid
from datetime import datetime, timezone

from app.config import settings
from app.schemas.admin import ConfigurationRule, Playbook
from app.schemas.analysis import Category, ChunkingConfig, CustomRule, Severity
from app.services import rules_rag
from app.storage.json_store import JsonListStore

logger = logging.getLogger(__name__)

_compliance: JsonListStore | None = None
_standards: JsonListStore | None = None
_owasp: JsonListStore | None = None
_playbooks: JsonListStore | None = None
_configurations: JsonListStore | None = None

_compliance_rule_ids: set[str] = set()
_standard_rule_ids: set[str] = set()
_owasp_rule_ids: set[str] = set()


def _compliance_store() -> JsonListStore:
    global _compliance
    if _compliance is None:
        _compliance = JsonListStore(settings.data_path / "compliance_rules.json", id_field="rule_id")
    return _compliance


def _standards_store() -> JsonListStore:
    global _standards
    if _standards is None:
        _standards = JsonListStore(settings.data_path / "coding_standards.json", id_field="rule_id")
    return _standards


def _owasp_store() -> JsonListStore:
    global _owasp
    if _owasp is None:
        _owasp = JsonListStore(settings.data_path / "owasp_rules.json", id_field="rule_id")
    return _owasp


def _playbooks_store() -> JsonListStore:
    global _playbooks
    if _playbooks is None:
        _playbooks = JsonListStore(settings.data_path / "playbooks.json", id_field="id")
    return _playbooks


def _configurations_store() -> JsonListStore:
    global _configurations
    if _configurations is None:
        _configurations = JsonListStore(settings.data_path / "configurations.json", id_field="id")
    return _configurations


def initialize() -> None:
    """Seed built-in OWASP rules on first run, then rebuild the RAG index from whatever's on
    disk - call once at app startup. The Static/Compliance agents refer to this store only;
    editing/adding rules here is the only way to change what they detect.
    """
    from app.detectors.owasp_seed import SEED_OWASP_RULES  # local import: avoids a detector<->store import cycle

    _owasp_store().seed_if_empty(SEED_OWASP_RULES)
    _reload_rag()


def _reload_rag() -> None:
    global _compliance_rule_ids, _standard_rule_ids, _owasp_rule_ids
    compliance_rules = [CustomRule(**r) for r in _compliance_store().all()]
    standard_rules = [CustomRule(**r) for r in _standards_store().all()]
    owasp_rules = [CustomRule(**r) for r in _owasp_store().all()]
    _compliance_rule_ids = {r.rule_id for r in compliance_rules}
    _standard_rule_ids = {r.rule_id for r in standard_rules}
    _owasp_rule_ids = {r.rule_id for r in owasp_rules}
    rules_rag.load_rules(compliance_rules + standard_rules + owasp_rules, ChunkingConfig())


def category_for_rule_id(rule_id: str) -> Category:
    if rule_id in _owasp_rule_ids:
        return Category.owasp
    if rule_id in _standard_rule_ids:
        return Category.coding_standard
    return Category.compliance


# --- Compliance Rules ---
def list_compliance_rules() -> list[CustomRule]:
    return [CustomRule(**r) for r in _compliance_store().all()]


def upsert_compliance_rule(rule: CustomRule) -> CustomRule:
    if not rule.rule_id:
        rule.rule_id = f"COMP-{uuid.uuid4().hex[:8]}"
    _compliance_store().upsert(rule.model_dump(mode="json"))
    _reload_rag()
    return rule


def delete_compliance_rule(rule_id: str) -> bool:
    ok = _compliance_store().delete(rule_id)
    if ok:
        _reload_rag()
    return ok


def bulk_import_compliance_rules(rules: list[CustomRule]) -> int:
    for rule in rules:
        if not rule.rule_id:
            rule.rule_id = f"COMP-{uuid.uuid4().hex[:8]}"
        _compliance_store().upsert(rule.model_dump(mode="json"))
    _reload_rag()
    return len(rules)


# --- Coding Standards ---
def list_coding_standards() -> list[CustomRule]:
    return [CustomRule(**r) for r in _standards_store().all()]


def upsert_coding_standard(rule: CustomRule) -> CustomRule:
    if not rule.rule_id:
        rule.rule_id = f"STD-{uuid.uuid4().hex[:8]}"
    _standards_store().upsert(rule.model_dump(mode="json"))
    _reload_rag()
    return rule


def delete_coding_standard(rule_id: str) -> bool:
    ok = _standards_store().delete(rule_id)
    if ok:
        _reload_rag()
    return ok


# --- OWASP Top 10 Rules (seeded from owasp_seed.py, then fully admin-managed) ---
def list_owasp_rules() -> list[CustomRule]:
    return [CustomRule(**r) for r in _owasp_store().all()]


def upsert_owasp_rule(rule: CustomRule) -> CustomRule:
    if not rule.rule_id:
        rule.rule_id = f"OWASP-{uuid.uuid4().hex[:8]}"
    _owasp_store().upsert(rule.model_dump(mode="json"))
    _reload_rag()
    return rule


def delete_owasp_rule(rule_id: str) -> bool:
    ok = _owasp_store().delete(rule_id)
    if ok:
        _reload_rag()
    return ok


# --- Playbooks (reference guidance; also fed as LLM context in the Security Reasoning Agent) ---
def list_playbooks() -> list[Playbook]:
    return [Playbook(**p) for p in _playbooks_store().all()]


def upsert_playbook(playbook: Playbook) -> Playbook:
    now = datetime.now(timezone.utc).isoformat()
    if not playbook.id:
        playbook.id = f"pb-{uuid.uuid4().hex[:8]}"
        playbook.created_at = now
    playbook.updated_at = now
    _playbooks_store().upsert(playbook.model_dump(mode="json"))
    return playbook


def delete_playbook(playbook_id: str) -> bool:
    return _playbooks_store().delete(playbook_id)


def playbooks_for_tags(tags: set[str]) -> list[Playbook]:
    tags_lower = {t.lower() for t in tags}
    matches = []
    for playbook in list_playbooks():
        if tags_lower & {t.lower() for t in playbook.tags}:
            matches.append(playbook)
    return matches


# --- Configurations (extra Configuration Agent regex patterns, admin-managed) ---
def list_configurations() -> list[ConfigurationRule]:
    return [ConfigurationRule(**c) for c in _configurations_store().all()]


def upsert_configuration(rule: ConfigurationRule) -> ConfigurationRule:
    if not rule.id:
        rule.id = f"cfg-{uuid.uuid4().hex[:8]}"
        rule.created_at = datetime.now(timezone.utc).isoformat()
    _configurations_store().upsert(rule.model_dump(mode="json"))
    return rule


def delete_configuration(rule_id: str) -> bool:
    return _configurations_store().delete(rule_id)


def compiled_configuration_rules() -> list[tuple[str, str, re.Pattern, Severity]]:
    compiled: list[tuple[str, str, re.Pattern, Severity]] = []
    for rule in list_configurations():
        try:
            pattern = re.compile(rule.pattern)
        except re.error:
            logger.warning("admin_store: skipping configuration rule %s, invalid pattern %r", rule.id, rule.pattern)
            continue
        compiled.append((rule.title, rule.description, pattern, rule.severity))
    return compiled
