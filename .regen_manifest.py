import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent / "trusted-tests"
manifest_path = root / "trusted-tests.manifest.json"
policy_id = json.loads(manifest_path.read_text(encoding="utf-8"))["policy_id"]

files = []
for path in sorted(root.rglob("*")):
    if path.is_dir():
        continue
    relative = path.relative_to(root)
    if relative.name == "trusted-tests.manifest.json" or "__pycache__" in relative.parts:
        continue
    files.append(
        {
            "path": relative.as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    )
files.sort(key=lambda entry: entry["path"])

document = {"schema_version": 1, "policy_id": policy_id, "files": files}
manifest_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
print("manifest_sha256=" + hashlib.sha256(manifest_path.read_bytes()).hexdigest())
print("file_count=" + str(len(files)))
