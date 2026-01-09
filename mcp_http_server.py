import argparse
import json
import logging
import os
import sys
import uvicorn
from contextlib import asynccontextmanager
from typing import Optional, List, Union, Dict, Any
from fastapi import FastAPI, Request, Response, APIRouter, HTTPException, Query, Path
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mcp_server")

def _ensure_local_imports():
    here = os.path.dirname(os.path.abspath(__file__))
    lib_dir = os.path.join(here, "ida-project-mcp")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)

_ensure_local_imports()

from project_store import ProjectStore
from mcp_service import McpService, McpError

# Global service instance
service = None
project_store = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global service, project_store
    project_path = os.environ.get("IDA_MCP_PROJECT", ".")
    try:
        project_store = ProjectStore(project_path)
        service = McpService(project_store)
        print(f"Loaded project from: {project_path}")
    except Exception as e:
        print(f"Failed to load project: {e}", file=sys.stderr)
        # We don't exit here to allow debugging, but service will be broken
    
    yield
    
    # Shutdown
    if project_store:
        project_store.close()

app = FastAPI(lifespan=lifespan)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- REST API Implementation ---

api_router = APIRouter(prefix="/api/v1")

def get_service():
    if not service:
        raise HTTPException(status_code=503, detail="Server not initialized")
    return service

def handle_mcp_error(e: McpError):
    if e.code == "NOT_FOUND":
        raise HTTPException(status_code=404, detail=e.message)
    elif e.code == "INVALID_ARGUMENT":
        raise HTTPException(status_code=400, detail=e.message)
    elif e.code == "UNSUPPORTED":
        raise HTTPException(status_code=501, detail=e.message)
    else:
        raise HTTPException(status_code=500, detail=e.message)

# Project Endpoints

@api_router.get("/project")
def get_project_overview():
    svc = get_service()
    try:
        return svc.get_project_overview()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/project/binaries")
def list_binaries(
    offset: int = 0,
    limit: int = 50,
    detail: bool = False
):
    svc = get_service()
    return svc.get_project_binaries(offset=offset, limit=limit, detail=detail)

# Binary Endpoints

@api_router.get("/binary/{binary_name}")
def get_binary_metadata(binary_name: str):
    svc = get_service()
    try:
        return svc.get_binary_metadata(binary_name)
    except Exception as e: # McpError is wrapped or raised directly? McpService raises standard exceptions or McpError?
        # McpService methods usually wrap and re-raise or just run. 
        # But looking at McpService code, _get_binary raises LookupError/KeyError.
        # Ideally we should catch those too.
        if isinstance(e, (LookupError, KeyError)):
             raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/sections")
def list_binary_sections(binary_name: str):
    svc = get_service()
    try:
        return svc.list_binary_sections(binary_name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/segments")
def list_binary_segments(binary_name: str):
    svc = get_service()
    try:
        return svc.list_binary_segments(binary_name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/functions")
def list_binary_functions(
    binary_name: str,
    query: Optional[str] = None,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.list_binary_functions(binary_name, query=query, offset=offset, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/imports")
def list_binary_imports(
    binary_name: str,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.list_binary_imports(binary_name, offset=offset, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/exports")
def list_binary_exports(
    binary_name: str,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.list_binary_exports(binary_name, offset=offset, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/symbols")
def list_binary_symbols(
    binary_name: str,
    query: Optional[str] = None,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.list_binary_symbols(binary_name, query=query, offset=offset, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/strings")
def list_binary_strings(
    binary_name: str,
    query: Optional[str] = None,
    min_length: Optional[int] = None,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.list_binary_strings(binary_name, query=query, min_length=min_length, offset=offset, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Analysis Endpoints

@api_router.get("/binary/{binary_name}/disassembly")
def get_binary_disassembly(
    binary_name: str,
    start_address: str = Query(..., description="Start address (hex or int)"),
    end_address: str = Query(..., description="End address (hex or int)")
):
    svc = get_service()
    try:
        return svc.get_binary_disassembly_text(binary_name, start_address, end_address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/function/{address}/disassembly")
def get_binary_function_disassembly(
    binary_name: str,
    address: str
):
    svc = get_service()
    try:
        return svc.get_binary_function_disassembly_text(binary_name, address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/function/{address}/pseudocode")
def get_binary_function_pseudocode(
    binary_name: str,
    address: str
):
    svc = get_service()
    try:
        # returns list of dicts, but we usually ask for one function here
        res = svc.get_binary_function_pseudocode_by_address(binary_name, address)
        if not res:
            raise HTTPException(status_code=404, detail="Pseudocode not found")
        return res[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/bytes")
def get_binary_bytes(
    binary_name: str,
    address: str,
    length: int,
    format_type: Optional[str] = None
):
    svc = get_service()
    try:
        return svc.get_binary_bytes(binary_name, address, length, format_type)
    except McpError as e:
        handle_mcp_error(e)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/address/{address}")
def resolve_address(
    binary_name: str,
    address: str
):
    svc = get_service()
    try:
        return svc.resolve_address(binary_name, address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/function/{address}/callers")
def get_callers(
    binary_name: str,
    address: str,
    depth: Optional[int] = None,
    limit: Optional[int] = None
):
    svc = get_service()
    try:
        return svc.get_binary_function_callers(binary_name, address, depth, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/function/{address}/callees")
def get_callees(
    binary_name: str,
    address: str,
    depth: Optional[int] = None,
    limit: Optional[int] = None
):
    svc = get_service()
    try:
        return svc.get_binary_function_callees(binary_name, address, depth, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/xrefs/to/{address}")
def get_xrefs_to(
    binary_name: str,
    address: str,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.get_binary_cross_references_to_address(binary_name, address, offset, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/binary/{binary_name}/xrefs/from/{address}")
def get_xrefs_from(
    binary_name: str,
    address: str,
    offset: int = 0,
    limit: int = 50
):
    svc = get_service()
    try:
        return svc.get_binary_cross_references_from_address(binary_name, address, offset, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Include the API router
app.include_router(api_router)

# --- End of REST API Implementation ---

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

@app.post("/{path:path}")
async def handle_mcp(path: str, request: Request):
    # Simple path check if needed, but we catch all POSTs for now
    # You can enforce path check if strictly required, e.g.:
    # if path != "mcp": return JSONResponse(status_code=404)
    
    try:
        body = await request.body()
        msg = json.loads(body.decode("utf-8")) if body else None
    except Exception:
        return JSONResponse(status_code=400, content=_jsonrpc_error(None, -32700, "Parse error"))

    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return JSONResponse(status_code=400, content=_jsonrpc_error(None, -32600, "Invalid Request"))

    mid = msg.get("id")
    method = msg.get("method")
    
    if "method" not in msg:
        # JSON-RPC notification? or invalid. Return accepted.
        return Response(status_code=202)

    if not service:
        return JSONResponse(status_code=503, content=_jsonrpc_error(mid, -32000, "Server not initialized"))

    try:
        resp = dispatch(msg)
        if resp is None:
            return Response(status_code=202)
        return JSONResponse(content=resp)
    except Exception as e:
        return JSONResponse(status_code=500, content=_jsonrpc_error(mid, -32603, f"Internal error: {e}"))

def dispatch(msg):
    mid = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}

    logger.info(f"MCP Request: method={method} params={json.dumps(params, ensure_ascii=False)}")

    if method == "initialize":
        pv = params.get("protocolVersion") or "2025-06-18"
        server_info = {"name": "ida-project-mcp", "version": "0.1.0"}
        result = {"protocolVersion": pv, "capabilities": {"tools": {}}, "serverInfo": server_info}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}

    if method == "tools/list":
        tools = [
            {"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]}
            for t in service.get_tools()
        ]
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}}

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not name:
            return _jsonrpc_error(mid, -32602, "Invalid params: name required")
        
        tools = service.get_tools()
        handler = next((t["handler"] for t in tools if t["name"] == name), None)
        if not handler:
            return {"jsonrpc": "2.0", "id": mid, "result": _tool_result(_err("NOT_FOUND", f"tool_not_found: {name}"), is_error=True)}
        
        try:
            res = handler(arguments)
            return {"jsonrpc": "2.0", "id": mid, "result": _tool_result(_ok(res))}
        except McpError as e:
            return {"jsonrpc": "2.0", "id": mid, "result": _tool_result(_err(e.code, e.message, e.details), is_error=True)}
        except Exception as e:
            import traceback
            return {"jsonrpc": "2.0", "id": mid, "result": _tool_result(
                _err("INTERNAL_ERROR", "tool_exception", {"error": str(e), "traceback": traceback.format_exc()}),
                is_error=True,
            )}

    return _jsonrpc_error(mid, -32601, f"Method not found: {method}")

def main():
    parser = argparse.ArgumentParser(description="IDA Project MCP server (FastAPI + Uvicorn)")
    parser.add_argument("--project", default=".", help="export_index.json or directory containing .db files")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (debug mode)")
    args = parser.parse_args()

    os.environ["IDA_MCP_PROJECT"] = args.project
    
    # Check if project path exists
    if not os.path.exists(args.project):
        print(f"Warning: Project path '{args.project}' does not exist.", file=sys.stderr)

    uvicorn.run(
        "mcp_http_server:app",
        host=args.host,
        port=args.port,
        reload=args.reload
    )

if __name__ == "__main__":
    main()
