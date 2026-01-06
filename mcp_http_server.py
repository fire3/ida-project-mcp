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
from mcp_service import McpService, McpError


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
        self.service = McpService(project_store)

    def list_tools(self):
        return [
            {"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]}
            for t in self.service.get_tools()
        ]

    def call_tool(self, name, arguments):
        tools = self.service.get_tools()
        handler = next((t["handler"] for t in tools if t["name"] == name), None)
        if not handler:
            return _tool_result(_err("NOT_FOUND", f"tool_not_found: {name}"), is_error=True)
        try:
            res = handler(arguments or {})
            return _tool_result(_ok(res))
        except McpError as e:
            return _tool_result(_err(e.code, e.message, e.details), is_error=True)
        except Exception as e:
            return _tool_result(
                _err("INTERNAL_ERROR", "tool_exception", {"error": str(e), "traceback": traceback.format_exc()}),
                is_error=True,
            )


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
