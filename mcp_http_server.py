import argparse
import json
import os
import re
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


def _ensure_local_imports():
    here = os.path.dirname(os.path.abspath(__file__))
    lib_dir = os.path.join(here, "ida-project-mcp")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)


_ensure_local_imports()

from project_store import ProjectStore


def _jsonrpc_error(id_value, code, message, data=None):
    err = {"code": int(code), "message": str(message)}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id_value, "error": err}


def _tool_result(payload, is_error=False):
    text = json.dumps(payload, ensure_ascii=False)
    return {"content": [{"type": "text", "text": text}], "isError": bool(is_error)}


def _ok(data):
    return {"ok": True, "data": data}


def _err(code, message, details=None):
    e = {"code": str(code), "message": str(message)}
    if details is not None:
        e["details"] = details
    return {"ok": False, "error": e}


def _get_origin_host(origin):
    if not origin:
        return None
    try:
        u = urlparse(origin)
        return u.hostname
    except Exception:
        return None


def _origin_allowed(origin):
    host = _get_origin_host(origin)
    if host is None:
        return True
    host = host.lower()
    return host in ("localhost", "127.0.0.1", "::1")


class McpToolRegistry:
    def __init__(self, project_store):
        self.project_store = project_store
        self._tools = self._build_tools()

    def list_tools(self):
        return [{"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]} for t in self._tools]

    def call_tool(self, name, arguments):
        fn = None
        for t in self._tools:
            if t["name"] == name:
                fn = t["handler"]
                break
        if fn is None:
            return _tool_result(_err("NOT_FOUND", f"tool_not_found: {name}"), is_error=True)
        try:
            res = fn(arguments or {})
            is_error = not bool(res.get("ok"))
            return _tool_result(res, is_error=is_error)
        except Exception as e:
            return _tool_result(
                _err("INTERNAL_ERROR", "tool_exception", {"error": str(e), "traceback": traceback.format_exc()}),
                is_error=True,
            )

    def _binary(self, args):
        bid = args.get("binary")
        if not bid:
            raise KeyError("binary_required")
        b = self.project_store.get_binary(bid)
        if not b:
            raise LookupError("binary_not_found")
        return b

    def _maybe_parse_json(self, value):
        if not isinstance(value, str):
            return value
        s = value.strip()
        if not s:
            return value
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
            try:
                return json.loads(s)
            except Exception:
                return value
        return value

    def _coerce_json_list(self, value):
        v = self._maybe_parse_json(value)
        if isinstance(v, tuple):
            return list(v)
        return v

    def _build_tools(self):
        return [
            {
                "name": "get_project_overview",
                "description": "Args: none. Returns: {project:string, binaries_count:int, backend:string, capabilities:object}. Notes: capabilities is an aggregated view across binaries and may be a subset.",
                "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}}, "additionalProperties": True},
                "handler": lambda args: _ok(self.project_store.get_overview()),
            },
            {
                "name": "get_project_binaries",
                "description": "Args: offset(int>=0), limit(int 1..500), detail(bool), filters(object). Returns: by default an array of {binary:string} where binary is the recommended identifier for other tools. If detail=true, returns extended records including binary_id, db_path, and best-effort metadata.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project": {"type": "string"},
                        "offset": {"type": "integer", "minimum": 0},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                        "filters": {"type": "object"},
                        "detail": {"type": "boolean"},
                    },
                    "additionalProperties": True,
                },
                "handler": lambda args: _ok(
                    self.project_store.get_project_binaries(
                        args.get("offset"), args.get("limit"), args.get("filters"), args.get("detail")
                    )
                ),
            },
            {
                "name": "get_binary_metadata",
                "description": "Args: binary(string). Returns: metadata object (best-effort), commonly including format, processor/arch, address width, hashes, image base, and entry points when available.",
                "inputSchema": {"type": "object", "properties": {"binary": {"type": "string"}}, "required": ["binary"]},
                "handler": lambda args: _ok(self._binary(args).get_metadata_dict()),
            },
            {
                "name": "get_backend_capabilities",
                "description": "Args: binary(string, optional). Returns: capability map (boolean flags) describing which features are available (e.g., decompile, disassemble, xrefs, callgraph, bytes, aob_search).",
                "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}, "binary": {"type": "string"}}},
                "handler": self._tool_get_backend_capabilities,
            },
            {
                "name": "list_binary_sections",
                "description": "Args: binary(string). Returns: array of section objects (best-effort). Error: may be empty if the backend does not provide sections.",
                "inputSchema": {"type": "object", "properties": {"binary": {"type": "string"}}, "required": ["binary"]},
                "handler": lambda args: _ok(self._binary(args).list_sections()),
            },
            {
                "name": "list_binary_segments",
                "description": "Args: binary(string). Returns: array of segment objects with start/end VA and permissions. Notes: used by byte-reading and address mapping.",
                "inputSchema": {"type": "object", "properties": {"binary": {"type": "string"}}, "required": ["binary"]},
                "handler": lambda args: _ok(self._binary(args).list_segments()),
            },
            {
                "name": "list_binary_imports",
                "description": "Args: binary(string), offset(int>=0, optional), limit(int, optional). Returns: array of imports (library, name, ordinal, address, thunk_address).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary"],
                },
                "handler": lambda args: _ok(self._binary(args).list_imports(args.get("offset"), args.get("limit"))),
            },
            {
                "name": "list_binary_exports",
                "description": "Args: binary(string), offset(int>=0, optional), limit(int, optional). Returns: array of exports (name, ordinal, address, forwarder).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary"],
                },
                "handler": lambda args: _ok(self._binary(args).list_exports(args.get("offset"), args.get("limit"))),
            },
            {
                "name": "list_binary_symbols",
                "description": "Args: binary(string), query(string, optional), offset(int>=0, optional), limit(int, optional). Returns: array of symbol entries (name, demangled_name, kind, address, size; fields are best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary": {"type": "string"},
                        "query": {"type": "string"},
                        "offset": {"type": "integer"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["binary"],
                },
                "handler": lambda args: _ok(self._binary(args).list_symbols(args.get("query"), args.get("offset"), args.get("limit"))),
            },
            {
                "name": "resolve_address",
                "description": "Args: binary(string), address(string|int). Returns: an object describing the address context (function, symbol, segment, section, string_ref, data_item) plus is_code/is_data booleans.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "address": {"type": "string"}},
                    "required": ["binary", "address"],
                },
                "handler": lambda args: _ok(self._binary(args).resolve_address(args.get("address"))),
            },
            {
                "name": "get_binary_bytes",
                "description": "Args: binary(string), address(string|int), length(int), format_type(string, optional). Returns: formatted byte dump text. Errors: UNSUPPORTED if the on-disk binary is not available; NOT_FOUND if address is unmapped; INVALID_ARGUMENT for bad parameters.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary": {"type": "string"},
                        "address": {"type": "string"},
                        "length": {"type": "integer"},
                        "format_type": {"type": "string"},
                    },
                    "required": ["binary", "address", "length"],
                },
                "handler": self._tool_get_binary_bytes,
            },
            {
                "name": "get_binary_decoded_data",
                "description": "Args: binary(string), address(string|int), length(int). Returns: decoded data description object (best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "address": {"type": "string"}, "length": {"type": "integer"}},
                    "required": ["binary", "address", "length"],
                },
                "handler": lambda args: _ok(self._binary(args).get_decoded_data(args.get("address"), args.get("length"))),
            },
            {
                "name": "get_binary_disassembly_text",
                "description": "Args: binary(string), start_address(string|int), end_address(string|int). Returns: plain text disassembly for the requested range (best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary": {"type": "string"},
                        "start_address": {"type": "string"},
                        "end_address": {"type": "string"},
                    },
                    "required": ["binary", "start_address", "end_address"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).get_disassembly_text(args.get("start_address"), args.get("end_address"))
                ),
            },
            {
                "name": "get_binary_function_disassembly_text",
                "description": "Args: binary(string), function_address(string|int). Returns: plain text disassembly for the function containing function_address (best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "function_address": {"type": "string"}},
                    "required": ["binary", "function_address"],
                },
                "handler": lambda args: _ok(self._binary(args).get_function_disassembly_text(args.get("function_address"))),
            },
            {
                "name": "get_binary_functions",
                "description": "Args: binary(string), query(string, optional), offset(int>=0, optional), limit(int, optional), filters(object, optional). Returns: array of function summaries with addresses/ranges/sizes and flags (is_thunk/is_library).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary": {"type": "string"},
                        "query": {"type": "string"},
                        "offset": {"type": "integer"},
                        "limit": {"type": "integer"},
                        "filters": {"type": "object"},
                    },
                    "required": ["binary"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).list_functions(args.get("query"), args.get("offset"), args.get("limit"), args.get("filters"))
                ),
            },
            {
                "name": "get_binary_function_by_name",
                "description": "Args: binary(string), names(string|array<string>), match(string, optional). names may also be a JSON-encoded array string. match: exact|prefix|contains|regex. Returns: array of matching functions with name, demangled_name, address, start_address, end_address, size.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary": {"type": "string"},
                        "names": {"type": ["array", "string"], "items": {"type": "string"}},
                        "match": {"type": "string"},
                    },
                    "required": ["binary", "names"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).get_functions_by_name(self._coerce_json_list(args.get("names")), args.get("match"))
                ),
            },
            {
                "name": "get_binary_function_by_address",
                "description": "Args: binary(string), addresses(string|int|array). addresses may also be a JSON-encoded array string. Returns: array of function objects containing the given addresses (best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary": {"type": "string"},
                        "addresses": {"type": ["array", "string", "integer"], "items": {}},
                    },
                    "required": ["binary", "addresses"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).get_functions_by_address(self._coerce_json_list(args.get("addresses")))
                ),
            },
            {
                "name": "get_binary_function_pseudo_code_by_address",
                "description": "Args: binary(string), addresses(string|int|array), options(object, optional). addresses may also be a JSON-encoded array string. Returns: array of {address,function,pseudocode,...} objects when decompiler output exists; otherwise may return an empty array.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary": {"type": "string"},
                        "addresses": {"type": ["array", "string", "integer"], "items": {}},
                        "options": {"type": "object"},
                    },
                    "required": ["binary", "addresses"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).get_pseudocode_by_address(self._coerce_json_list(args.get("addresses")), args.get("options"))
                ),
            },
            {
                "name": "get_binary_function_callees",
                "description": "Args: binary(string), function_address(string|int), depth(int, optional), limit(int, optional). Returns: array of callees/call edges (best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "function_address": {"type": "string"}, "depth": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary", "function_address"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).get_callees(args.get("function_address"), args.get("depth"), args.get("limit"))
                ),
            },
            {
                "name": "get_binary_function_callers",
                "description": "Args: binary(string), function_address(string|int), depth(int, optional), limit(int, optional). Returns: array of callers/call edges (best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "function_address": {"type": "string"}, "depth": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary", "function_address"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).get_callers(args.get("function_address"), args.get("depth"), args.get("limit"))
                ),
            },
            {
                "name": "get_binary_cross_references_to_address",
                "description": "Args: binary(string), address(string|int), offset(int>=0, optional), limit(int, optional), filters(object, optional). Returns: array of xref entries (best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary": {"type": "string"},
                        "address": {"type": "string"},
                        "offset": {"type": "integer"},
                        "limit": {"type": "integer"},
                        "filters": {"type": "object"},
                    },
                    "required": ["binary", "address"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).get_xrefs_to_address(args.get("address"), args.get("offset"), args.get("limit"), args.get("filters"))
                ),
            },
            {
                "name": "get_binary_cross_references_from_address",
                "description": "Args: binary(string), address(string|int), offset(int>=0, optional), limit(int, optional). Returns: array of xref entries (best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "address": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary", "address"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).get_xrefs_from_address(args.get("address"), args.get("offset"), args.get("limit"))
                ),
            },
            {
                "name": "list_binary_strings",
                "description": "Args: binary(string), query(string, optional), min_length(int, optional), encodings(string|array<string>, optional), offset(int>=0, optional), limit(int, optional). Returns: array of string records (address, encoding, length, string, section_name when available).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary": {"type": "string"},
                        "query": {"type": "string"},
                        "min_length": {"type": "integer"},
                        "encodings": {"type": ["array", "string"], "items": {"type": "string"}},
                        "offset": {"type": "integer"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["binary"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).list_strings(
                        args.get("query"),
                        args.get("min_length"),
                        self._coerce_json_list(args.get("encodings")),
                        args.get("offset"),
                        args.get("limit"),
                    )
                ),
            },
            {
                "name": "get_string_xrefs",
                "description": "Args: binary(string), string_address(string|int), offset(int>=0, optional), limit(int, optional). Returns: array of xref entries referencing the string address (best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "string_address": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary", "string_address"],
                },
                "handler": lambda args: _ok(self._binary(args).get_string_xrefs(args.get("string_address"), args.get("offset"), args.get("limit"))),
            },
            {
                "name": "search_string_symbol_in_binary",
                "description": "Args: binary(string), search_string(string), match(string, optional). match: contains|exact|regex. Returns: array of string records matching the search criteria (best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "search_string": {"type": "string"}, "match": {"type": "string"}},
                    "required": ["binary", "search_string"],
                },
                "handler": self._tool_search_string_in_binary,
            },
            {
                "name": "search_immediates_in_binary",
                "description": "Args: binary(string), value(any), width(int, optional), offset(int>=0, optional), limit(int, optional). Returns: array of hits where the immediate value is used (best-effort).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "value": {}, "width": {"type": "integer"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary", "value"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).search_immediates(args.get("value"), args.get("width"), args.get("offset"), args.get("limit"))
                ),
            },
            {
                "name": "search_bytes_pattern_in_binary",
                "description": "Args: binary(string), pattern(string), offset(int>=0, optional), limit(int, optional). pattern example: \"48 8B ?? ?? 89\". Returns: array of hit records/addresses (best-effort). Errors: INVALID_ARGUMENT for malformed patterns; UNSUPPORTED if binary bytes are not available.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "pattern": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary", "pattern"],
                },
                "handler": self._tool_search_bytes_pattern_in_binary,
            },
            {
                "name": "search_string_symbol_in_project",
                "description": "Args: search_string(string), match(string, optional), offset(int>=0, optional), limit(int, optional). match: contains|exact|regex. Returns: array of hits including {binary:string, ...string_record}.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"search_string": {"type": "string"}, "match": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["search_string"],
                },
                "handler": self._tool_search_string_in_project,
            },
            {
                "name": "search_exported_function_in_project",
                "description": "Args: function_name(string), match(string, optional), offset(int>=0, optional), limit(int, optional). match: exact|contains|regex. Returns: array of hits including {binary:string, export:object}.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"function_name": {"type": "string"}, "match": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["function_name"],
                },
                "handler": self._tool_search_export_in_project,
            },
            {
                "name": "search_similar_functions_in_project",
                "description": "Args: binary(string), function_address(string|int), top_k(int, optional), threshold(number, optional). Returns: UNSUPPORTED (no similarity index available in this backend).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "function_address": {"type": "string"}, "top_k": {"type": "integer"}, "threshold": {"type": "number"}},
                    "required": ["binary", "function_address"],
                },
                "handler": lambda args: _err("UNSUPPORTED", "similarity_index_not_available"),
            },
        ]

    def _tool_get_backend_capabilities(self, args):
        bid = args.get("binary")
        if bid:
            b = self._binary({"binary": bid})
            return _ok(b.get_capabilities())
        return _ok(self.project_store.get_overview().get("capabilities") or {})

    def _tool_get_binary_bytes(self, args):
        b = self._binary(args)
        try:
            return _ok(b.get_bytes(args.get("address"), args.get("length"), args.get("format_type")))
        except LookupError as e:
            return _err("NOT_FOUND", str(e))
        except RuntimeError as e:
            return _err("UNSUPPORTED", str(e))
        except ValueError as e:
            return _err("INVALID_ARGUMENT", str(e))

    def _tool_search_string_in_binary(self, args):
        b = self._binary(args)
        s = args.get("search_string")
        match = (args.get("match") or "contains").lower()
        if match == "exact":
            hits = b.list_strings(query=s, offset=0, limit=500)
            hits = [h for h in hits if h.get("string") == s]
            return _ok(hits)
        if match == "regex":
            try:
                rx = re.compile(s)
            except Exception as e:
                return _err("INVALID_ARGUMENT", "regex_invalid", {"error": str(e)})
            hits = b.list_strings(query=None, offset=0, limit=500)
            hits = [h for h in hits if isinstance(h.get("string"), str) and rx.search(h["string"])]
            return _ok(hits)
        return _ok(b.list_strings(query=s, offset=0, limit=500))

    def _tool_search_bytes_pattern_in_binary(self, args):
        b = self._binary(args)
        try:
            return _ok(b.search_bytes_pattern(args.get("pattern"), args.get("offset"), args.get("limit")))
        except RuntimeError as e:
            return _err("UNSUPPORTED", str(e))
        except ValueError as e:
            return _err("INVALID_ARGUMENT", str(e))

    def _tool_search_string_in_project(self, args):
        s = args.get("search_string")
        match = (args.get("match") or "contains").lower()
        offset = 0 if args.get("offset") is None else max(0, int(args.get("offset")))
        limit = 50 if args.get("limit") is None else min(500, max(1, int(args.get("limit"))))
        all_hits = []
        for b in self.project_store.list_binaries():
            hits = []
            if match == "exact":
                hits = b.list_strings(query=s, offset=0, limit=500)
                hits = [h for h in hits if h.get("string") == s]
            elif match == "regex":
                try:
                    rx = re.compile(s)
                except Exception as e:
                    return _err("INVALID_ARGUMENT", "regex_invalid", {"error": str(e)})
                cand = b.list_strings(query=None, offset=0, limit=500)
                hits = [h for h in cand if isinstance(h.get("string"), str) and rx.search(h["string"])]
            else:
                hits = b.list_strings(query=s, offset=0, limit=500)
            for h in hits:
                all_hits.append({"binary": b.display_name, **h})
        return _ok(all_hits[offset : offset + limit])

    def _tool_search_export_in_project(self, args):
        fn = args.get("function_name")
        match = (args.get("match") or "exact").lower()
        offset = 0 if args.get("offset") is None else max(0, int(args.get("offset")))
        limit = 50 if args.get("limit") is None else min(500, max(1, int(args.get("limit"))))
        hits = []
        for b in self.project_store.list_binaries():
            exports = b.list_exports(offset=0, limit=500)
            for ex in exports:
                name = ex.get("name") or ""
                ok = False
                if match == "exact":
                    ok = name == fn
                elif match == "contains":
                    ok = fn in name
                elif match == "regex":
                    try:
                        ok = re.search(fn, name) is not None
                    except Exception:
                        ok = False
                if ok:
                    hits.append({"binary": b.display_name, "export": ex})
        return _ok(hits[offset : offset + limit])


class McpHttpHandler(BaseHTTPRequestHandler):
    server_version = "ida-project-mcp/0.1"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == self.server.mcp_path:
            self.send_response(405)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if not _origin_allowed(self.headers.get("Origin")):
            self.send_response(403)
            self.end_headers()
            return

        parsed = urlparse(self.path)
        if parsed.path != self.server.mcp_path:
            self.send_response(404)
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length") or "0")
        except Exception:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""
        try:
            msg = json.loads(body.decode("utf-8")) if body else None
        except Exception:
            self._send_json(400, _jsonrpc_error(None, -32700, "Parse error"))
            return

        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            self._send_json(400, _jsonrpc_error(None, -32600, "Invalid Request"))
            return

        if "method" not in msg:
            self.send_response(202)
            self.end_headers()
            return

        resp = self.server.dispatch(msg)
        if resp is None:
            self.send_response(202)
            self.end_headers()
            return
        self._send_json(200, resp)

    def log_message(self, fmt, *args):
        return

    def _send_json(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class McpHttpServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler_cls, mcp_path, project_store, server_info):
        super().__init__(server_address, handler_cls)
        self.mcp_path = mcp_path
        self.project_store = project_store
        self.server_info = server_info
        self.tools = McpToolRegistry(project_store)

    def dispatch(self, msg):
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        if method == "initialize":
            pv = params.get("protocolVersion") or "2025-06-18"
            result = {"protocolVersion": pv, "capabilities": {"tools": {}}, "serverInfo": self.server_info}
            return {"jsonrpc": "2.0", "id": mid, "result": result}

        if method == "ping":
            return {"jsonrpc": "2.0", "id": mid, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": mid, "result": {"tools": self.tools.list_tools()}}

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not name:
                return _jsonrpc_error(mid, -32602, "Invalid params: name required")
            return {"jsonrpc": "2.0", "id": mid, "result": self.tools.call_tool(name, arguments)}

        return _jsonrpc_error(mid, -32601, f"Method not found: {method}")


def _create_http_server(project, host, port, path):
    store = ProjectStore(project)
    server_info = {"name": "ida-project-mcp", "version": "0.1.0"}
    httpd = McpHttpServer((host, int(port)), McpHttpHandler, path, store, server_info)
    return httpd, store


def _import_qt():
    try:
        from PySide6 import QtCore, QtGui, QtWidgets

        return QtCore, QtGui, QtWidgets
    except Exception:
        pass
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets

        return QtCore, QtGui, QtWidgets
    except Exception:
        return None


def _run_gui(initial_project=".", initial_host="127.0.0.1", initial_port=8765, initial_path="/mcp"):
    qt = _import_qt()
    if not qt:
        print("Error: PySide6/PyQt5 not available. Please install one of them.", file=sys.stderr)
        raise SystemExit(1)
    QtCore, QtGui, QtWidgets = qt

    class MainWindow(QtWidgets.QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("IDA Project MCP HTTP Server")

            self._httpd = None
            self._store = None
            self._thread = None

            central = QtWidgets.QWidget(self)
            self.setCentralWidget(central)

            form = QtWidgets.QFormLayout()

            self.project_edit = QtWidgets.QLineEdit()
            self.project_edit.setText(str(initial_project))

            project_row = QtWidgets.QHBoxLayout()
            project_row.addWidget(self.project_edit, 1)
            self.pick_dir_btn = QtWidgets.QPushButton("选择目录")
            self.pick_file_btn = QtWidgets.QPushButton("选择 export_index.json")
            project_row.addWidget(self.pick_dir_btn)
            project_row.addWidget(self.pick_file_btn)
            form.addRow("Project", project_row)

            self.host_edit = QtWidgets.QLineEdit()
            self.host_edit.setText(str(initial_host))
            form.addRow("Host", self.host_edit)

            self.port_spin = QtWidgets.QSpinBox()
            self.port_spin.setRange(1, 65535)
            self.port_spin.setValue(int(initial_port))
            form.addRow("Port", self.port_spin)

            self.path_edit = QtWidgets.QLineEdit()
            self.path_edit.setText(str(initial_path))
            form.addRow("Path", self.path_edit)

            btn_row = QtWidgets.QHBoxLayout()
            self.start_btn = QtWidgets.QPushButton("启动")
            self.stop_btn = QtWidgets.QPushButton("关闭")
            self.copy_btn = QtWidgets.QPushButton("复制URL")
            self.stop_btn.setEnabled(False)
            btn_row.addWidget(self.start_btn)
            btn_row.addWidget(self.stop_btn)
            btn_row.addWidget(self.copy_btn)

            self.status_label = QtWidgets.QLabel("idle")
            self.log_box = QtWidgets.QPlainTextEdit()
            self.log_box.setReadOnly(True)
            self.log_box.setMaximumBlockCount(2000)

            layout = QtWidgets.QVBoxLayout(central)
            layout.addLayout(form)
            layout.addLayout(btn_row)
            layout.addWidget(self.status_label)
            layout.addWidget(self.log_box, 1)

            self.pick_dir_btn.clicked.connect(self._pick_dir)
            self.pick_file_btn.clicked.connect(self._pick_file)
            self.start_btn.clicked.connect(self._start_server)
            self.stop_btn.clicked.connect(self._stop_server)
            self.copy_btn.clicked.connect(self._copy_url)

        def _append_log(self, s):
            self.log_box.appendPlainText(str(s))

        def _current_url(self):
            host = self.host_edit.text().strip() or "127.0.0.1"
            port = int(self.port_spin.value())
            path = self.path_edit.text().strip() or "/mcp"
            if not path.startswith("/"):
                path = "/" + path
            return f"http://{host}:{port}{path}"

        def _pick_dir(self):
            d = QtWidgets.QFileDialog.getExistingDirectory(self, "选择导出目录", os.path.abspath(self.project_edit.text() or "."))
            if d:
                self.project_edit.setText(d)

        def _pick_file(self):
            p, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "选择 export_index.json", os.path.abspath(self.project_edit.text() or "."), "JSON (*.json);;All Files (*)"
            )
            if p:
                self.project_edit.setText(p)

        def _start_server(self):
            if self._httpd is not None:
                return
            project = self.project_edit.text().strip() or "."
            host = self.host_edit.text().strip() or "127.0.0.1"
            port = int(self.port_spin.value())
            path = self.path_edit.text().strip() or "/mcp"
            if not path.startswith("/"):
                path = "/" + path
                self.path_edit.setText(path)
            try:
                httpd, store = _create_http_server(project, host, port, path)
            except OSError as e:
                self.status_label.setText(f"bind_failed: {e}")
                self._append_log(f"bind_failed: {e}")
                return
            except Exception as e:
                self.status_label.setText(f"start_failed: {e}")
                self._append_log(f"start_failed: {e}")
                return

            th = threading.Thread(target=httpd.serve_forever, daemon=True)
            th.start()
            self._httpd = httpd
            self._store = store
            self._thread = th

            self.status_label.setText("running")
            self._append_log(f"running: {self._current_url()}")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)

        def _stop_server(self):
            if self._httpd is None:
                return
            httpd = self._httpd
            store = self._store
            th = self._thread
            self._httpd = None
            self._store = None
            self._thread = None

            try:
                httpd.shutdown()
            except Exception:
                pass
            try:
                httpd.server_close()
            except Exception:
                pass
            if th:
                try:
                    th.join(timeout=2.0)
                except Exception:
                    pass
            if store:
                try:
                    store.close()
                except Exception:
                    pass

            self.status_label.setText("stopped")
            self._append_log("stopped")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

        def _copy_url(self):
            url = self._current_url()
            cb = QtGui.QGuiApplication.clipboard()
            cb.setText(url)
            self._append_log(f"copied: {url}")

        def closeEvent(self, event):
            try:
                self._stop_server()
            except Exception:
                pass
            event.accept()

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
    w = MainWindow()
    w.resize(920, 480)
    w.show()
    raise SystemExit(app.exec())


def main():
    ap = argparse.ArgumentParser(description="IDA Project MCP server (Streamable HTTP)")
    ap.add_argument("--project", default=".", help="export_index.json 或包含 .db 的目录")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--path", default="/mcp", help="MCP endpoint path")
    ap.add_argument("--gui", action="store_true", help="Launch Qt GUI")
    args = ap.parse_args()

    if args.gui:
        _run_gui(args.project, args.host, args.port, args.path)
        return

    httpd, store = _create_http_server(args.project, args.host, args.port, args.path)
    try:
        httpd.serve_forever()
    finally:
        try:
            store.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()

