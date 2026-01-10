import sqlite3
import os
import json

class BinaryDatabase:
    def __init__(self, db_path, logger=None):
        self.db_path = db_path
        self.logger = logger
        self.conn = None
        self.cursor = None

    def log(self, msg):
        if self.logger:
            self.logger.log(msg)
        else:
            print(f"[DB] {msg}")

    def connect(self):
        # Remove existing db if it exists to start fresh
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                self.log(f"Warning: Could not remove existing DB at {self.db_path}")

        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.log(f"Connected to database: {self.db_path}")

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None
            self.log("Database connection closed.")

    def commit(self):
        if self.conn:
            self.conn.commit()

    def create_schema(self):
        self.log("Creating schema...")
        
        # 6.0 Metadata (Single JSON Blob)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata_json (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                content TEXT
            )
        """)

        # 6.1 Segments
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS segments (
                seg_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                start_va INTEGER,
                end_va INTEGER,
                perm_r INTEGER,
                perm_w INTEGER,
                perm_x INTEGER,
                file_offset INTEGER,
                type TEXT
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_segments_range ON segments(start_va, end_va)")

        # 6.1 Sections (Optional/Raw)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS sections (
                sec_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                start_va INTEGER,
                end_va INTEGER,
                file_offset INTEGER,
                entropy REAL,
                type TEXT
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_sections_range ON sections(start_va, end_va)")

        # 6.2 Imports
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS imports (
                import_id INTEGER PRIMARY KEY AUTOINCREMENT,
                library TEXT,
                name TEXT,
                ordinal INTEGER,
                address INTEGER,
                thunk_address INTEGER
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_imports_name ON imports(name)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_imports_library ON imports(library)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_imports_address ON imports(address)")

        # 6.2 Exports
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS exports (
                export_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                ordinal INTEGER,
                address INTEGER,
                forwarder TEXT
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_exports_name ON exports(name)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_exports_address ON exports(address)")

        # 6.2 Symbols
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS symbols (
                symbol_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                demangled_name TEXT,
                kind TEXT,
                address INTEGER,
                size INTEGER
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_symbols_demangled ON symbols(demangled_name)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_symbols_address ON symbols(address)")

        # 6.3 Functions
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS functions (
                function_va INTEGER PRIMARY KEY,
                name TEXT,
                demangled_name TEXT,
                start_va INTEGER,
                end_va INTEGER,
                size INTEGER,
                is_thunk INTEGER,
                is_library INTEGER
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_functions_range ON functions(start_va, end_va)")

        # 6.3 Functions R-Tree (Virtual Table)
        try:
            self.cursor.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS functions_rtree USING rtree(
                    function_va,
                    start_va,
                    end_va
                )
            """)
        except sqlite3.OperationalError:
            self.log("Warning: R-Tree module not available. Skipping functions_rtree.")

        # 6.4 Pseudocode
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS pseudocode (
                function_va INTEGER PRIMARY KEY,
                content TEXT
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_pseudocode_func ON pseudocode(function_va)")

        # 6.5 Disassembly Chunks
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS disasm_chunks (
                start_va INTEGER PRIMARY KEY,
                end_va INTEGER,
                content TEXT
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_disasm_chunks_range ON disasm_chunks(start_va, end_va)")

        # 6.6 Data Items
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS data_items (
                address INTEGER PRIMARY KEY,
                size INTEGER,
                kind TEXT,
                type_name TEXT,
                repr TEXT,
                target_va INTEGER
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_data_items_kind ON data_items(kind)")

        # 6.7 Strings
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS strings (
                string_id INTEGER PRIMARY KEY AUTOINCREMENT,
                address INTEGER,
                encoding TEXT,
                length INTEGER,
                string TEXT,
                section_name TEXT
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_strings_address ON strings(address)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_strings_content ON strings(string)")

        # 6.8 Xrefs
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS xrefs (
                xref_id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_va INTEGER,
                to_va INTEGER,
                from_function_va INTEGER,
                to_function_va INTEGER,
                xref_type TEXT,
                operand_index INTEGER
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs(to_va)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(from_va)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_xrefs_from_func ON xrefs(from_function_va)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_xrefs_to_func ON xrefs(to_function_va)")

        # 6.9 Call Edges
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS call_edges (
                caller_function_va INTEGER,
                callee_function_va INTEGER,
                call_site_va INTEGER,
                call_type TEXT,
                PRIMARY KEY (caller_function_va, call_site_va)
            )
        """)
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_call_edges_caller ON call_edges(caller_function_va)")
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_call_edges_callee ON call_edges(callee_function_va)")

        # 6.10 Local Types
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS local_types (
                type_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                content TEXT
            )
        """)
        
        self.conn.commit()
        self.log("Schema created successfully.")

    # Data Insertion Methods
    
    def insert_metadata_json(self, json_content):
        self.cursor.execute("""
            INSERT OR REPLACE INTO metadata_json (id, content)
            VALUES (1, ?)
        """, (json_content,))
        self.conn.commit()

    def insert_segments(self, segments_data):
        # segments_data: list of (name, start_va, end_va, perm_r, perm_w, perm_x, file_offset, type)
        self.cursor.executemany("""
            INSERT INTO segments (name, start_va, end_va, perm_r, perm_w, perm_x, file_offset, type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, segments_data)
        self.conn.commit()

    def insert_sections(self, sections_data):
        # sections_data: list of (name, start_va, end_va, file_offset, entropy, type)
        self.cursor.executemany("""
            INSERT INTO sections (name, start_va, end_va, file_offset, entropy, type)
            VALUES (?, ?, ?, ?, ?, ?)
        """, sections_data)
        self.conn.commit()

    def insert_imports(self, imports_data):
        # imports_data: list of (library, name, ordinal, address, thunk_address)
        self.cursor.executemany("""
            INSERT INTO imports (library, name, ordinal, address, thunk_address)
            VALUES (?, ?, ?, ?, ?)
        """, imports_data)
        self.conn.commit()

    def insert_exports(self, exports_data):
        # exports_data: list of (name, ordinal, address, forwarder)
        self.cursor.executemany("""
            INSERT INTO exports (name, ordinal, address, forwarder)
            VALUES (?, ?, ?, ?)
        """, exports_data)
        self.conn.commit()

    def insert_symbols(self, symbols_data):
        # symbols_data: list of (name, demangled_name, kind, address, size)
        self.cursor.executemany("""
            INSERT INTO symbols (name, demangled_name, kind, address, size)
            VALUES (?, ?, ?, ?, ?)
        """, symbols_data)
        self.conn.commit()

    def insert_functions(self, functions_data, rtree_data=None):
        # functions_data: list of (function_va, name, demangled_name, start_va, end_va, size, is_thunk, is_library)
        self.cursor.executemany("""
            INSERT INTO functions (function_va, name, demangled_name, start_va, end_va, size, is_thunk, is_library)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, functions_data)
        
        if rtree_data:
            try:
                self.cursor.executemany("""
                    INSERT INTO functions_rtree (function_va, start_va, end_va)
                    VALUES (?, ?, ?)
                """, rtree_data)
            except sqlite3.OperationalError:
                pass
        self.conn.commit()

    def insert_pseudocode(self, pseudocode_data):
        # pseudocode_data: list of (function_va, content)
        self.cursor.executemany("""
            INSERT INTO pseudocode (function_va, content)
            VALUES (?, ?)
        """, pseudocode_data)
        self.conn.commit()

    def insert_disasm_chunks(self, chunks_data):
        # chunks_data: list of (start_va, end_va, content)
        self.cursor.executemany("""
            INSERT INTO disasm_chunks (start_va, end_va, content)
            VALUES (?, ?, ?)
        """, chunks_data)
        self.conn.commit()

    def insert_data_items(self, data_items_list):
        # data_items_list: list of (address, size, kind, type_name, repr, target_va)
        self.cursor.executemany("""
            INSERT INTO data_items (address, size, kind, type_name, repr, target_va)
            VALUES (?, ?, ?, ?, ?, ?)
        """, data_items_list)
        self.conn.commit()

    def insert_strings(self, strings_data):
        # strings_data: list of (address, encoding, length, string, section_name)
        self.cursor.executemany("""
            INSERT INTO strings (address, encoding, length, string, section_name)
            VALUES (?, ?, ?, ?, ?)
        """, strings_data)
        self.conn.commit()

    def insert_xrefs(self, xrefs_data):
        # xrefs_data: list of (from_va, to_va, from_function_va, to_function_va, xref_type, operand_index)
        self.cursor.executemany("""
            INSERT INTO xrefs (from_va, to_va, from_function_va, to_function_va, xref_type, operand_index)
            VALUES (?, ?, ?, ?, ?, ?)
        """, xrefs_data)
        self.conn.commit()

    def insert_call_edges(self, call_edges_data):
        # call_edges_data: list of (caller_function_va, callee_function_va, call_site_va, call_type)
        self.cursor.executemany("""
            INSERT OR IGNORE INTO call_edges (caller_function_va, callee_function_va, call_site_va, call_type)
            VALUES (?, ?, ?, ?)
        """, call_edges_data)
        self.conn.commit()

    def insert_local_types(self, name, content):
        self.cursor.execute("""
            INSERT INTO local_types (name, content)
            VALUES (?, ?)
        """, (name, content))
        self.conn.commit()
