import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic_settings import BaseSettings


ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(ENV_FILE, override=False)

# LangSmith currently documents LANGSMITH_* names, while older LangChain
# examples used LANGCHAIN_*. Keep both populated so tracing works across the
# pinned package versions in this project and current LangSmith defaults.
_LANGSMITH_ENV_ALIASES = {
    "LANGSMITH_TRACING": "LANGCHAIN_TRACING_V2",
    "LANGSMITH_API_KEY": "LANGCHAIN_API_KEY",
    "LANGSMITH_PROJECT": "LANGCHAIN_PROJECT",
}
for current_name, legacy_name in _LANGSMITH_ENV_ALIASES.items():
    if not os.getenv(current_name) and os.getenv(legacy_name):
        os.environ[current_name] = os.environ[legacy_name]
    if not os.getenv(legacy_name) and os.getenv(current_name):
        os.environ[legacy_name] = os.environ[current_name]


class Settings(BaseSettings):
    openai_api_key: str = ""
    openai_api_base: str = ""
    openai_model: str = "azure/genailab-maas-gpt-4o-mini"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    github_token: str = ""
    osv_api_url: str = "https://api.osv.dev/v1/querybatch"
    langsmith_api_key: str = ""
    langsmith_endpoint: str = ""
    langsmith_project: str = "SecureCodeGuardrailAuditor"
    langsmith_finops_days: int = 30
    langsmith_finops_limit: int = 200
    langsmith_finops_cache_seconds: int = 300
    log_level: str = "INFO"
    jwt_secret: str = "change-me"
    jwt_expiry_minutes: int = 720
    data_dir: str = "./data"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def data_path(self) -> Path:
        path = Path(self.data_dir)
        (path / "repos").mkdir(parents=True, exist_ok=True)
        return path

    class Config:
        env_file = str(ENV_FILE)
        extra = "ignore"


settings = Settings()
