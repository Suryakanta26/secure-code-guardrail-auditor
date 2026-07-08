from pathlib import Path

_SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".c", ".cpp", ".h", ".hpp", ".yml", ".yaml", ".json", ".env",
    ".toml", ".ini", ".cfg", ".sh", ".tf", ".txt",
}
_MAX_FILE_BYTES = 200_000
_MAX_FILES = 300


def is_scannable(filename: str) -> bool:
    """Check if a file name is permitted for scanning."""
    path = Path(filename)
    name_lower = path.name.lower()
    return (
        path.suffix.lower() in _SCANNABLE_EXTENSIONS
        or name_lower == "dockerfile"
        or name_lower.startswith(".env")
    )
