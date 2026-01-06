import argparse
import json
import os
import re
import sys
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

    def _build_tools(self):
        return [
            {
                "name": "get_project_overview",
                "description": "获取项目概览（包含二进制数量、索引状态、后端类型等）。",
                "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}}, "additionalProperties": True},
                "handler": lambda args: _ok(self.project_store.get_overview()),
            },
            {
                "name": "get_project_binaries",
                "description": "获取项目中的所有二进制文件。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project": {"type": "string"},
                        "offset": {"type": "integer", "minimum": 0},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                        "filters": {"type": "object"},
                    },
                    "additionalProperties": True,
                },
                "handler": lambda args: _ok(
                    self.project_store.get_project_binaries(args.get("offset"), args.get("limit"), args.get("filters"))
                ),
            },
            {
                "name": "get_binary_metadata",
                "description": "获取指定二进制的元数据。",
                "inputSchema": {"type": "object", "properties": {"binary": {"type": "string"}}, "required": ["binary"]},
                "handler": lambda args: _ok(self._binary(args).get_metadata_dict()),
            },
            {
                "name": "get_backend_capabilities",
                "description": "返回当前后端可用能力与限制。",
                "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}, "binary": {"type": "string"}}},
                "handler": self._tool_get_backend_capabilities,
            },
            {
                "name": "list_binary_sections",
                "description": "获取节区（section）列表与属性。",
                "inputSchema": {"type": "object", "properties": {"binary": {"type": "string"}}, "required": ["binary"]},
                "handler": lambda args: _ok(self._binary(args).list_sections()),
            },
            {
                "name": "list_binary_segments",
                "description": "获取段（segment）列表与属性。",
                "inputSchema": {"type": "object", "properties": {"binary": {"type": "string"}}, "required": ["binary"]},
                "handler": lambda args: _ok(self._binary(args).list_segments()),
            },
            {
                "name": "list_binary_imports",
                "description": "获取导入表（含导入库、符号、IAT/PLT 地址等）。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary"],
                },
                "handler": lambda args: _ok(self._binary(args).list_imports(args.get("offset"), args.get("limit"))),
            },
            {
                "name": "list_binary_exports",
                "description": "获取导出表（函数/变量）。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary"],
                },
                "handler": lambda args: _ok(self._binary(args).list_exports(args.get("offset"), args.get("limit"))),
            },
            {
                "name": "list_binary_symbols",
                "description": "获取符号（含本地/全局/调试符号，按后端能力）。",
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
                "description": "将地址解析为所在函数/符号/段节/字符串/指令等上下文。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "address": {"type": "string"}},
                    "required": ["binary", "address"],
                },
                "handler": lambda args: _ok(self._binary(args).resolve_address(args.get("address"))),
            },
            {
                "name": "get_binary_bytes",
                "description": "读取指定虚地址处的原始字节，并格式化二进制数据。",
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
                "description": "获取某地址处的结构化数据信息。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "address": {"type": "string"}, "length": {"type": "integer"}},
                    "required": ["binary", "address", "length"],
                },
                "handler": lambda args: _ok(self._binary(args).get_decoded_data(args.get("address"), args.get("length"))),
            },
            {
                "name": "get_binary_disassembly_text",
                "description": "获取指定地址范围的反汇编结果。",
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
                "description": "获取指定函数的反汇编结果。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "function_address": {"type": "string"}},
                    "required": ["binary", "function_address"],
                },
                "handler": lambda args: _ok(self._binary(args).get_function_disassembly_text(args.get("function_address"))),
            },
            {
                "name": "get_binary_functions",
                "description": "列出二进制中的函数（可筛选/搜索）。",
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
                "description": "根据名称查找函数。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "names": {}, "match": {"type": "string"}},
                    "required": ["binary", "names"],
                },
                "handler": lambda args: _ok(self._binary(args).get_functions_by_name(args.get("names"), args.get("match"))),
            },
            {
                "name": "get_binary_function_by_address",
                "description": "根据地址查找所属函数。",
                "inputSchema": {"type": "object", "properties": {"binary": {"type": "string"}, "addresses": {}}, "required": ["binary", "addresses"]},
                "handler": lambda args: _ok(self._binary(args).get_functions_by_address(args.get("addresses"))),
            },
            {
                "name": "get_binary_function_pseudo_code_by_address",
                "description": "获取指定函数的反编译伪代码。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "addresses": {}, "options": {"type": "object"}},
                    "required": ["binary", "addresses"],
                },
                "handler": lambda args: _ok(self._binary(args).get_pseudocode_by_address(args.get("addresses"), args.get("options"))),
            },
            {
                "name": "get_binary_function_callees",
                "description": "获取指定函数调用的被调用者（callee）。",
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
                "description": "获取调用指定函数的调用者（caller）。",
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
                "description": "获取对指定地址的交叉引用（Xref To）。",
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
                "description": "获取从指定地址发出的交叉引用（Xref From）。",
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
                "description": "枚举二进制中的字符串。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary": {"type": "string"},
                        "query": {"type": "string"},
                        "min_length": {"type": "integer"},
                        "encodings": {},
                        "offset": {"type": "integer"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["binary"],
                },
                "handler": lambda args: _ok(
                    self._binary(args).list_strings(
                        args.get("query"),
                        args.get("min_length"),
                        args.get("encodings"),
                        args.get("offset"),
                        args.get("limit"),
                    )
                ),
            },
            {
                "name": "get_string_xrefs",
                "description": "获取对某字符串地址的引用。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "string_address": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary", "string_address"],
                },
                "handler": lambda args: _ok(self._binary(args).get_string_xrefs(args.get("string_address"), args.get("offset"), args.get("limit"))),
            },
            {
                "name": "search_string_symbol_in_binary",
                "description": "在二进制中查找指定字符串。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "search_string": {"type": "string"}, "match": {"type": "string"}},
                    "required": ["binary", "search_string"],
                },
                "handler": self._tool_search_string_in_binary,
            },
            {
                "name": "search_immediates_in_binary",
                "description": "搜索立即数/常量在代码中的使用位置。",
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
                "description": "AOB/字节模式搜索（支持通配符）。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}, "pattern": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["binary", "pattern"],
                },
                "handler": self._tool_search_bytes_pattern_in_binary,
            },
            {
                "name": "search_string_symbol_in_project",
                "description": "在项目中查找所有包含指定字符串的二进制与位置。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"search_string": {"type": "string"}, "match": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["search_string"],
                },
                "handler": self._tool_search_string_in_project,
            },
            {
                "name": "search_exported_function_in_project",
                "description": "在项目中查找导出指定函数名称的二进制。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"function_name": {"type": "string"}, "match": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"}},
                    "required": ["function_name"],
                },
                "handler": self._tool_search_export_in_project,
            },
            {
                "name": "search_similar_functions_in_project",
                "description": "按函数特征相似度在项目内检索（需要索引能力）。",
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
                all_hits.append({"binary": b.binary_id, **h})
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
                    hits.append({"binary": b.binary_id, "export": ex})
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


def main():
    ap = argparse.ArgumentParser(description="IDA Project MCP server (Streamable HTTP)")
    ap.add_argument("--project", default=".", help="export_index.json 或包含 .db 的目录")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--path", default="/mcp", help="MCP endpoint path")
    args = ap.parse_args()

    store = ProjectStore(args.project)
    server_info = {"name": "ida-project-mcp", "version": "0.1.0"}
    httpd = McpHttpServer((args.host, int(args.port)), McpHttpHandler, args.path, store, server_info)
    try:
        httpd.serve_forever()
    finally:
        try:
            store.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()

