import json
import struct
import zipfile
from io import BytesIO
from pathlib import Path


def extract_crx(crx_path: str, dest_dir: Path) -> dict:
    """Giai nen CRX (bo header, lay ZIP body), tra ve manifest dict."""
    with open(crx_path, "rb") as f:
        content = f.read()
    if content[:4] != b"Cr24":
        raise ValueError(f"Not a CRX file (magic={content[:4]})")

    version = struct.unpack("<I", content[4:8])[0]
    if version == 2:
        pubkey_len = struct.unpack("<I", content[8:12])[0]
        sig_len = struct.unpack("<I", content[12:16])[0]
        header_size = 16 + pubkey_len + sig_len
    elif version == 3:
        header_size_field = struct.unpack("<I", content[8:12])[0]
        header_size = 12 + header_size_field
    else:
        raise ValueError(f"Unsupported CRX version: {version}")

    zip_data = content[header_size:]
    if zip_data[:2] != b"PK":
        raise ValueError("Invalid ZIP body")

    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(BytesIO(zip_data)) as zf:
        zf.extractall(dest_dir)
    return json.loads((dest_dir / "manifest.json").read_text(encoding="utf-8"))