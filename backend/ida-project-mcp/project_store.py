import json
import os

from binary_dbquery import BinaryDbQuery


class ProjectStore:
    def __init__(self, project_path):
        self.project_path = os.path.abspath(project_path) if project_path else os.getcwd()
        self.project_id = os.path.basename(self.project_path.rstrip("\\/")) or "default"
        self._binaries = {}
        self._binary_order = []
        self._aliases = {}
        self._load()

    def close(self):
        for b in self._binaries.values():
            try:
                b.close()
            except Exception:
                pass

    def _load(self):
        index_path = self._resolve_index_path(self.project_path)
        if index_path:
            base_dir = os.path.dirname(index_path)
            with open(index_path, "r", encoding="utf-8") as f:
                idx = json.load(f)
            
            # Process target
            target = idx.get("target")
            if target and target.get("db"):
                db_rel = target.get("db")
                db_full = os.path.join(base_dir, db_rel)
                rec = {
                    "db": db_full,
                    "display_name": target.get("name"),
                    "role": "main",
                }
                self._add_binary(rec)

            # Process dependencies
            dependencies = idx.get("dependencies") or []
            for item in dependencies:
                db_rel = item.get("db")
                if not db_rel:
                    continue
                db_full = os.path.join(base_dir, db_rel)
                rec = {
                    "db": db_full,
                    "display_name": item.get("name"),
                    "role": "dep",
                }
                self._add_binary(rec)
            return

        if os.path.isdir(self.project_path):
            for fn in sorted(os.listdir(self.project_path)):
                if fn.lower().endswith(".db"):
                    db_path = os.path.join(self.project_path, fn)
                    self._add_binary({"db": db_path, "display_name": fn, "role": None})

    def _resolve_index_path(self, project_path):
        if not project_path:
            return None
        if os.path.isfile(project_path) and os.path.basename(project_path).lower() == "export_index.json":
            return project_path
        if os.path.isdir(project_path):
            cand = os.path.join(project_path, "export_index.json")
            if os.path.exists(cand):
                return cand
        return None

    def _add_binary(self, rec):
        db_path = os.path.abspath(rec["db"])
        if not os.path.exists(db_path):
            return
        q = BinaryDbQuery(
            db_path=db_path,
            binary_id=os.path.basename(db_path),
            display_name=rec.get("display_name"),
        )
        meta = {}
        try:
            meta = q.get_metadata_dict()
        except Exception:
            meta = {}
        sha256 = meta.get("sha256") if isinstance(meta, dict) else None
        binary_id = sha256 or os.path.basename(db_path)
        q.binary_id = binary_id
        if binary_id in self._binaries:
            try:
                q.close()
            except Exception:
                pass
            return
        self._binaries[binary_id] = q
        self._binary_order.append(binary_id)
        self._add_alias(q.display_name, binary_id)
        self._add_alias(os.path.basename(db_path), binary_id)

    def _add_alias(self, alias, binary_id):
        if not alias:
            return
        key = str(alias)
        self._aliases.setdefault(key, set()).add(binary_id)
        self._aliases.setdefault(key.lower(), set()).add(binary_id)

    def get_binary(self, binary_name):
        if binary_name is None:
            return None
        key = str(binary_name)
        # Try direct ID lookup first
        b = self._binaries.get(key)
        if b is not None:
            return b
        # Try alias lookup
        candidates = self._aliases.get(key) or self._aliases.get(key.lower())
        if not candidates or len(candidates) != 1:
            return None
        cid = next(iter(candidates))
        return self._binaries.get(cid)

    def list_binaries(self):
        return [self._binaries[i] for i in self._binary_order if i in self._binaries]

    def get_overview(self):
        caps = {}
        bins = self.list_binaries()
        for b in bins:
            for k, v in (b.get_capabilities() or {}).items():
                if v:
                    caps[k] = True
        return {
            "project": self.project_id,
            "binaries_count": len(bins),
            "analysis_status": "ready",
            "backend": "sqlite",
            "capabilities": caps,
        }

    def get_project_binaries(self, offset=None, limit=None, filters=None, detail=False):
        offset = 0 if offset is None else max(0, int(offset))
        limit = 50 if limit is None else min(500, max(1, int(limit)))
        filters = filters or {}
        out = []
        for b in self.list_binaries():
            out.append({
                "binary_name": b.display_name,
            })
        return out[offset : offset + limit]
