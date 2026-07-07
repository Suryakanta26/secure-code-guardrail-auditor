from pydantic import BaseModel

from app.schemas.analysis import Severity


class ConfigurationRule(BaseModel):
    id: str = ""
    title: str
    description: str
    pattern: str
    severity: Severity
    created_at: str = ""


class Playbook(BaseModel):
    id: str = ""
    title: str
    category: str = "General"
    body: str
    tags: list[str] = []
    created_at: str = ""
    updated_at: str = ""
