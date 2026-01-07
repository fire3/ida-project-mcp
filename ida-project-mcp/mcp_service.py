import json
import re
import inspect
import traceback
from typing import Any, Dict, List, Optional, Union, get_type_hints
from project_store import ProjectStore

def mcp_tool(name=None):
    """Decorator to mark a method as an MCP tool."""
    def decorator(func):
        func._mcp_tool_config = {
            "name": name or func.__name__,
        }
        return func
    return decorator

class McpError(Exception):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

class McpService:
    def __init__(self, project_store: ProjectStore):
        self.project_store = project_store

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get the list of registered tools with generated schemas."""
        tools = []
        for attr_name in dir(self):
            method = getattr(self, attr_name)
            if hasattr(method, "_mcp_tool_config"):
                cfg = method._mcp_tool_config
                
                # Generate schema and handler
                schema = self._generate_schema(method)
                handler = self._create_handler(method)
                
                description = method.__doc__.strip() if method.__doc__ else ""
                
                tools.append({
                    "name": cfg["name"],
                    "description": description,
                    "inputSchema": schema,
                    "handler": handler
                })
        return tools

    def _generate_schema(self, method) -> Dict[str, Any]:
        """Generate JSON schema from method signature."""
        sig = inspect.signature(method)
        type_hints = get_type_hints(method)
        
        properties = {}
        required = []
        
        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue
                
            param_type = type_hints.get(param_name, Any)
            json_type = self._python_type_to_json_type(param_type)
            
            properties[param_name] = json_type
            
            if param.default == inspect.Parameter.empty:
                required.append(param_name)
                
        return {
            "type": "object",
            "properties": properties,
            "required": required
        }

    def _python_type_to_json_type(self, py_type) -> Dict[str, Any]:
        """Convert Python type to JSON schema type."""
        if py_type == str:
            return {"type": "string"}
        elif py_type == int:
            return {"type": "integer"}
        elif py_type == bool:
            return {"type": "boolean"}
        elif py_type == float:
            return {"type": "number"}
        elif py_type == list or getattr(py_type, "__origin__", None) == list:
            return {"type": "array"}
        elif py_type == dict or getattr(py_type, "__origin__", None) == dict:
            return {"type": "object"}
        elif getattr(py_type, "__origin__", None) == Union:
            # Handle Optional (Union[T, None]) or Union[A, B]
            args = py_type.__args__
            # Simple case: Optional[T] -> T's type
            non_none = [a for a in args if a is not type(None)]
            if len(non_none) == 1:
                return self._python_type_to_json_type(non_none[0])
            # Complex Union: treat as any/string for now or multi-type
            return {} 
        else:
            return {} # Any or unknown

    def _create_handler(self, method):
        """Create a wrapper handler that binds arguments."""
        def handler(args: Dict[str, Any]):
            # Bind arguments to method signature
            sig = inspect.signature(method)
            try:
                bound_args = sig.bind(**args)
                bound_args.apply_defaults()
            except TypeError as e:
                 raise McpError("INVALID_ARGUMENT", str(e))
            return method(*bound_args.args, **bound_args.kwargs)
        return handler

    def _get_binary(self, binary_name: str):
        if not binary_name:
            raise KeyError("binary_name_required")
        b = self.project_store.get_binary(binary_name)
        if not b:
            raise LookupError(f"binary_not_found: {binary_name}")
        return b

    # --- Tool Definitions ---

    @mcp_tool(name="get_project_overview")
    def get_project_overview(self) -> Dict[str, Any]:
        """Get overview of the project including binaries count and capabilities.

        Returns:
            dict: Project overview information containing 'binaries_count' (int) and 'capabilities' (dict).
        """
        return self.project_store.get_overview()

    @mcp_tool(name="get_project_binaries")
    def get_project_binaries(self, offset: int = 0, limit: int = 50, filters: dict = None, detail: bool = False) -> List[Dict[str, Any]]:
        """Get list of binaries in the project.

        Args:
            offset: Start index for pagination (default: 0).
            limit: Maximum number of binaries to return (default: 50).
            filters: Dictionary of filters to apply (optional).
            detail: Whether to include detailed information (default: False).
        Returns:
            list: List of dictionaries, each representing a binary with its metadata.
        """
        return self.project_store.get_project_binaries(offset, limit, filters, detail)

    @mcp_tool(name="get_binary_metadata")
    def get_binary_metadata(self, binary_name: str) -> Dict[str, Any]:
        """Get metadata for a specific binary.

        Args:
            binary_name: Binary name (string).
        Returns:
            dict: Metadata of the binary including architecture, file type, etc.
        """
        return self._get_binary(binary_name).get_metadata_dict()

    @mcp_tool(name="get_backend_capabilities")
    def get_backend_capabilities(self, binary_name: str = None) -> Dict[str, bool]:
        """Get capabilities of the backend or a specific binary.

        Args:
            binary_name: Binary name (string, optional). If provided, returns capabilities for that binary.
        Returns:
            dict: Capabilities dictionary where keys are capability names and values are booleans.
        """
        if binary_name:
            return self._get_binary(binary_name).get_capabilities()
        return self.project_store.get_overview().get("capabilities") or {}

    @mcp_tool(name="list_binary_sections")
    def list_binary_sections(self, binary_name: str) -> List[Dict[str, Any]]:
        """List sections in the binary.

        Args:
            binary_name: Binary name (string).
        Returns:
            list: List of dictionaries, each representing a section (name, start_address, size, etc.).
        """
        return self._get_binary(binary_name).list_sections()

    @mcp_tool(name="list_binary_segments")
    def list_binary_segments(self, binary_name: str) -> List[Dict[str, Any]]:
        """List segments in the binary.

        Args:
            binary_name: Binary name (string).
        Returns:
            list: List of dictionaries, each representing a segment (name, start_address, size, permissions).
        """
        return self._get_binary(binary_name).list_segments()

    @mcp_tool(name="list_binary_imports")
    def list_binary_imports(self, binary_name: str, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """List imports in the binary.

        Args:
            binary_name: Binary name (string).
            offset: Start index for pagination (default: 0).
            limit: Maximum number of imports to return (default: 50).
        Returns:
            list: List of dictionaries, each representing an imported function or symbol.
        """
        return self._get_binary(binary_name).list_imports(offset, limit)

    @mcp_tool(name="list_binary_exports")
    def list_binary_exports(self, binary_name: str, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """List exports in the binary.

        Args:
            binary_name: Binary name (string).
            offset: Start index for pagination (default: 0).
            limit: Maximum number of exports to return (default: 50).
        Returns:
            list: List of dictionaries, each representing an exported function or symbol.
        """
        return self._get_binary(binary_name).list_exports(offset, limit)

    @mcp_tool(name="list_binary_symbols")
    def list_binary_symbols(self, binary_name: str, query: str = None, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """List symbols in the binary.

        Args:
            binary_name: Binary name (string).
            query: Search query string (optional).
            offset: Start index for pagination (default: 0).
            limit: Maximum number of symbols to return (default: 50).
        Returns:
            list: List of dictionaries, each representing a symbol.
        """
        return self._get_binary(binary_name).list_symbols(query, offset, limit)

    @mcp_tool(name="resolve_address")
    def resolve_address(self, binary_name: str, address: Union[str, int]) -> Dict[str, Any]:
        """Resolve information about an address.

        Args:
            binary_name: Binary name (string).
            address: Address to resolve (hex string or integer).
        Returns:
            dict: Information about the address, including location (function, block, instruction).
        """
        return self._get_binary(binary_name).resolve_address(address)

    @mcp_tool(name="get_binary_bytes")
    def get_binary_bytes(self, binary_name: str, address: Union[str, int], length: int, format_type: str = None) -> str:
        """Get bytes from the binary.

        Args:
            binary_name: Binary name (string).
            address: Start address to read bytes from (hex string or integer).
            length: Number of bytes to read.
            format_type: Output format (optional, e.g., 'hex', 'base64').
        Returns:
            str: The bytes read, formatted as requested.
        """
        try:
            return self._get_binary(binary_name).get_bytes(address, length, format_type)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except RuntimeError as e:
            raise McpError("UNSUPPORTED", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))

    @mcp_tool(name="get_binary_decoded_data")
    def get_binary_decoded_data(self, binary_name: str, address: Union[str, int], length: int) -> Dict[str, Any]:
        """Get decoded data from the binary.

        Args:
            binary_name: Binary name (string).
            address: Start address to read data from (hex string or integer).
            length: Number of bytes to read.
        Returns:
            dict: Decoded data information.
        """
        return self._get_binary(binary_name).get_decoded_data(address, length)

    @mcp_tool(name="get_binary_disassembly_text")
    def get_binary_disassembly_text(self, binary_name: str, start_address: Union[str, int], end_address: Union[str, int]) -> str:
        """Get disassembly text for a range.

        Args:
            binary_name: Binary name (string).
            start_address: Start address of the range (hex string or integer).
            end_address: End address of the range (hex string or integer).
        Returns:
            str: Disassembly text for the specified range.
        """
        return self._get_binary(binary_name).get_disassembly_text(start_address, end_address)

    @mcp_tool(name="get_binary_function_disassembly_text")
    def get_binary_function_disassembly_text(self, binary_name: str, function_address: Union[str, int]) -> str:
        """Get disassembly text for a function.

        Args:
            binary_name: Binary name (string).
            function_address: Address of the function (hex string or integer).
        Returns:
            str: Disassembly text for the entire function.
        """
        return self._get_binary(binary_name).get_function_disassembly_text(function_address)

    @mcp_tool(name="get_binary_functions")
    def get_binary_functions(self, binary_name: str, query: str = None, offset: int = 0, limit: int = 50, filters: dict = None) -> List[Dict[str, Any]]:
        """List functions in the binary.

        Args:
            binary_name: Binary name (string).
            query: Search query for function names (optional).
            offset: Start index for pagination (default: 0).
            limit: Maximum number of functions to return (default: 50).
            filters: Dictionary of filters (optional).
        Returns:
            list: List of dictionaries, each representing a function (name, address, size).
        """
        return self._get_binary(binary_name).list_functions(query, offset, limit, filters)

    @mcp_tool(name="get_binary_function_by_name")
    def get_binary_function_by_name(self, binary_name: str, names: Union[str, List[str]], match: str = None) -> List[Dict[str, Any]]:
        """Get functions by name.

        Args:
            binary_name: Binary name (string).
            names: Function name(s) (string or list of strings).
            match: Matching mode ('exact', 'contains', 'regex').
        Returns:
            list: List of dictionaries, each representing a matching function.
        """
        if isinstance(names, str):
            # Try parsing as JSON if it looks like one, or wrap in list
            names = self._coerce_json_list(names)
        if not isinstance(names, list):
            names = [names]
        return self._get_binary(binary_name).get_functions_by_name(names, match)

    @mcp_tool(name="get_binary_function_by_address")
    def get_binary_function_by_address(self, binary_name: str, addresses: Union[str, int, List[Union[str, int]]]) -> List[Dict[str, Any]]:
        """Get function information in the project by address(es).

        Args:
            binary_name: Binary name (string).
            addresses: Function address(es) (hexadecimal or integer). Can be a single address, a comma-separated string, or a list of addresses.
        Returns:
            list: A list of dictionaries mapping addresses to function information (name, address, size) or error info.
        """
        if isinstance(addresses, (str, int)):
             addresses = self._coerce_json_list(addresses)
        if not isinstance(addresses, list):
            addresses = [addresses]
        return self._get_binary(binary_name).get_functions_by_address(addresses)

    @mcp_tool(name="get_binary_function_pseudocode_by_address")
    def get_binary_function_pseudocode_by_address(self, binary_name: str, addresses: Union[str, int, List[Union[str, int]]], options: dict = None) -> List[Dict[str, Any]]:
        """Get pseudocode for functions.

        Args:
            binary_name: Binary name (string).
            addresses: Function address(es) (hexadecimal or integer). Can be a single address, a comma-separated string, or a list of addresses.
            options: Options for decompilation (optional).
        Returns:
            list: List of dictionaries containing pseudocode for the requested functions.
        """
        if isinstance(addresses, (str, int)):
             addresses = self._coerce_json_list(addresses)
        if not isinstance(addresses, list):
            addresses = [addresses]
        return self._get_binary(binary_name).get_pseudocode_by_address(addresses, options)

    @mcp_tool(name="get_binary_function_callees")
    def get_binary_function_callees(self, binary_name: str, function_address: Union[str, int], depth: int = None, limit: int = None) -> List[Dict[str, Any]]:
        """Get callees of a function.

        Args:
            binary_name: Binary name (string).
            function_address: Address of the function (hex string or integer).
            depth: Recursion depth (optional).
            limit: Maximum number of callees to return (optional).
        Returns:
            list: List of dictionaries, each representing a called function.
        """
        return self._get_binary(binary_name).get_callees(function_address, depth, limit)

    @mcp_tool(name="get_binary_function_callers")
    def get_binary_function_callers(self, binary_name: str, function_address: Union[str, int], depth: int = None, limit: int = None) -> List[Dict[str, Any]]:
        """Get callers of a function.

        Args:
            binary_name: Binary name (string).
            function_address: Address of the function (hex string or integer).
            depth: Recursion depth (optional).
            limit: Maximum number of callers to return (optional).
        Returns:
            list: List of dictionaries, each representing a calling function.
        """
        return self._get_binary(binary_name).get_callers(function_address, depth, limit)

    @mcp_tool(name="get_binary_cross_references_to_address")
    def get_binary_cross_references_to_address(self, binary_name: str, address: Union[str, int], offset: int = 0, limit: int = 50, filters: dict = None) -> List[Dict[str, Any]]:
        """Get cross references to an address.

        Args:
            binary_name: Binary name (string).
            address: Target address (hex string or integer).
            offset: Start index for pagination (default: 0).
            limit: Maximum number of xrefs to return (default: 50).
            filters: Filters for xrefs (optional).
        Returns:
            list: List of dictionaries, each representing a cross reference.
        """
        return self._get_binary(binary_name).get_xrefs_to_address(address, offset, limit, filters)

    @mcp_tool(name="get_binary_cross_references_from_address")
    def get_binary_cross_references_from_address(self, binary_name: str, address: Union[str, int], offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Get cross references from an address.

        Args:
            binary_name: Binary name (string).
            address: Source address (hex string or integer).
            offset: Start index for pagination (default: 0).
            limit: Maximum number of xrefs to return (default: 50).
        Returns:
            list: List of dictionaries, each representing a cross reference.
        """
        return self._get_binary(binary_name).get_xrefs_from_address(address, offset, limit)

    @mcp_tool(name="list_binary_strings")
    def list_binary_strings(self, binary_name: str, query: str = None, min_length: int = None, encodings: Union[str, List[str]] = None, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """List strings in the binary.

        Args:
            binary_name: Binary name (string).
            query: Search query for strings (optional).
            min_length: Minimum string length (optional).
            encodings: List of encodings to search (optional).
            offset: Start index for pagination (default: 0).
            limit: Maximum number of strings to return (default: 50).
        Returns:
            list: List of dictionaries, each representing a found string.
        """
        if encodings:
            encodings = self._coerce_json_list(encodings)
        return self._get_binary(binary_name).list_strings(query, min_length, encodings, offset, limit)

    @mcp_tool(name="get_string_xrefs")
    def get_string_xrefs(self, binary_name: str, string_address: Union[str, int], offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Get cross references to a string.

        Args:
            binary_name: Binary name (string).
            string_address: Address of the string (hex string or integer).
            offset: Start index for pagination (default: 0).
            limit: Maximum number of xrefs to return (default: 50).
        Returns:
            list: List of dictionaries, each representing a cross reference to the string.
        """
        return self._get_binary(binary_name).get_string_xrefs(string_address, offset, limit)

    @mcp_tool(name="search_string_symbol_in_binary")
    def search_string_symbol_in_binary(self, binary_name: str, search_string: str, match: str = "contains") -> List[Dict[str, Any]]:
        """Search for string/symbol in binary.

        Args:
            binary_name: Binary name (string).
            search_string: The string or symbol name to search for.
            match: Matching mode ('exact', 'contains', 'regex'). Default is 'contains'.
        Returns:
            list: List of dictionaries, each representing a match.
        """
        b = self._get_binary(binary_name)
        match = (match or "contains").lower()
        if match == "exact":
            hits = b.list_strings(query=search_string, offset=0, limit=500)
            hits = [h for h in hits if h.get("string") == search_string]
            return hits
        if match == "regex":
            try:
                rx = re.compile(search_string)
            except Exception as e:
                raise McpError("INVALID_ARGUMENT", "regex_invalid", {"error": str(e)})
            hits = b.list_strings(query=None, offset=0, limit=500)
            hits = [h for h in hits if isinstance(h.get("string"), str) and rx.search(h["string"])]
            return hits
        return b.list_strings(query=search_string, offset=0, limit=500)

    @mcp_tool(name="search_immediates_in_binary")
    def search_immediates_in_binary(self, binary_name: str, value: Any, width: int = None, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for immediate values.

        Args:
            binary_name: Binary name (string).
            value: The immediate value to search for.
            width: Width of the value in bytes (optional).
            offset: Start index for pagination (default: 0).
            limit: Maximum number of matches to return (default: 50).
        Returns:
            list: List of dictionaries, each representing a match.
        """
        return self._get_binary(binary_name).search_immediates(value, width, offset, limit)

    @mcp_tool(name="search_bytes_pattern_in_binary")
    def search_bytes_pattern_in_binary(self, binary_name: str, pattern: str, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for byte pattern.

        Args:
            binary_name: Binary name (string).
            pattern: Byte pattern string (e.g., "E8 ?? ?? ?? ??").
            offset: Start index for pagination (default: 0).
            limit: Maximum number of matches to return (default: 50).
        Returns:
            list: List of dictionaries, each representing a match.
        """
        b = self._get_binary(binary_name)
        try:
            return b.search_bytes_pattern(pattern, offset, limit)
        except RuntimeError as e:
            raise McpError("UNSUPPORTED", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))

    @mcp_tool(name="search_string_symbol_in_project")
    def search_string_symbol_in_project(self, search_string: str, match: str = "contains", offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for string/symbol in project.

        Args:
            search_string: The string or symbol name to search for.
            match: Matching mode ('exact', 'contains', 'regex'). Default is 'contains'.
            offset: Start index for pagination (default: 0).
            limit: Maximum number of matches to return (default: 50).
        Returns:
            list: List of dictionaries, each representing a match across binaries.
        """
        match = (match or "contains").lower()
        offset = max(0, offset)
        limit = min(500, max(1, limit))
        
        all_hits = []
        for b in self.project_store.list_binaries():
            hits = []
            if match == "exact":
                hits = b.list_strings(query=search_string, offset=0, limit=500)
                hits = [h for h in hits if h.get("string") == search_string]
            elif match == "regex":
                try:
                    rx = re.compile(search_string)
                except Exception as e:
                    raise McpError("INVALID_ARGUMENT", "regex_invalid", {"error": str(e)})
                cand = b.list_strings(query=None, offset=0, limit=500)
                hits = [h for h in cand if isinstance(h.get("string"), str) and rx.search(h["string"])]
            else:
                hits = b.list_strings(query=search_string, offset=0, limit=500)
            
            for h in hits:
                all_hits.append({"binary": b.display_name, **h})
        return all_hits[offset : offset + limit]

    @mcp_tool(name="search_exported_function_in_project")
    def search_exported_function_in_project(self, function_name: str, match: str = "exact", offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for exported function in project.

        Args:
            function_name: The name of the exported function to search for.
            match: Matching mode ('exact', 'contains', 'regex'). Default is 'exact'.
            offset: Start index for pagination (default: 0).
            limit: Maximum number of matches to return (default: 50).
        Returns:
            list: List of dictionaries, each representing a match.
        """
        match = (match or "exact").lower()
        offset = max(0, offset)
        limit = min(500, max(1, limit))
        
        hits = []
        for b in self.project_store.list_binaries():
            exports = b.list_exports(offset=0, limit=500)
            for ex in exports:
                name = ex.get("name") or ""
                ok = False
                if match == "exact":
                    ok = name == function_name
                elif match == "contains":
                    ok = function_name in name
                elif match == "regex":
                    try:
                        ok = re.search(function_name, name) is not None
                    except Exception:
                        ok = False
                if ok:
                    hits.append({"binary": b.display_name, "export": ex})
        return hits[offset : offset + limit]

    @mcp_tool(name="search_similar_functions_in_project")
    def search_similar_functions_in_project(self, binary_name: str, function_address: Union[str, int], top_k: int = None, threshold: float = None) -> None:
        """Search similar functions.

        Args:
            binary_name: Binary name (string).
            function_address: Address of the function to find similarities for (hex string or integer).
            top_k: Number of similar functions to return (optional).
            threshold: Similarity threshold (optional).
        Returns:
            None: Currently raises McpError("UNSUPPORTED").
        """
        raise McpError("UNSUPPORTED", "similarity_index_not_available")

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
        if isinstance(v, list):
            return v
        if isinstance(v, tuple):
            return list(v)
        if isinstance(v, str) and "," in v:
            return [x.strip() for x in v.split(",") if x.strip()]
        return v
