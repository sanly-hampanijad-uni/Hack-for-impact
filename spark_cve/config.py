"""Read the application's own local NVD key file without exporting secrets."""
import getpass
import os
from pathlib import Path
import shlex


DEFAULT_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


def load_nvd_key(*, env_file=None, prompt=False):
    # Explicit prompt wins; process environment wins over a local settings file.
    if prompt:
        return getpass.getpass("NVD API key (not saved): ").strip() or None
    if os.getenv("NVD_API_KEY"):
        return os.environ["NVD_API_KEY"].strip() or None
    path = Path(env_file) if env_file is not None else DEFAULT_ENV_FILE
    if not path.exists() and env_file is None:
        return None
    # Never discover .env inside the repository being investigated. Do not
    # interpolate variables, execute shell syntax, or populate os.environ.
    key = None
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, separator, value = line.partition("=")
        if not separator or name.strip() != "NVD_API_KEY":
            continue
        try:
            parts = shlex.split(value, comments=True, posix=True)
        except ValueError:
            raise ValueError(f"Invalid NVD_API_KEY quoting in .env at line {number}") from None
        if len(parts) > 1:
            raise ValueError(f"Invalid NVD_API_KEY value in .env at line {number}")
        key = parts[0] if parts else None
    return key or None
