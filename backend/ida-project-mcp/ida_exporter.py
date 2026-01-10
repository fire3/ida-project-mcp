import sys
import os
import hashlib
import zlib
import json
import time
import datetime

# IDA Imports
try:
    import idapro
    import ida_kernwin
    import ida_auto
    import ida_loader
    import ida_pro
    import ida_nalt
    import ida_segment
    import ida_funcs
    import ida_bytes
    import ida_name
    import ida_entry
    import ida_xref
    import ida_typeinf
    import ida_hexrays
    import ida_lines
    import ida_gdl
    import ida_strlist
    import idautils
    import idc
    import ida_ida
except ImportError:
    pass # Expecting to run inside IDA

from ida_utils import ProgressTracker, calculate_entropy

class IDAExporter:
    def __init__(self, db, logger, timer, input_file=None):
        self.db = db
        self.log = logger.log
        self.timer = timer
        self.input_file = input_file

    def get_binary_info_dict(self):
        """Extract all metadata about the loaded binary in IDA and return as a complete dictionary matching frontend requirements.
        
        Returns:
            dict: A dictionary containing the final metadata structure.
        """
        # Get binary path and name
        binary_path = self.input_file or ida_nalt.get_input_file_path()
        binary_name = os.path.basename(binary_path) if binary_path else "unknown"
        file_exists = binary_path and os.path.exists(binary_path)
        
        # Calculate Hashes & Size
        hashes = {"md5": "", "sha256": "", "crc32": ""}
        file_size = 0
        
        if file_exists:
            try:
                with open(binary_path, 'rb') as f:
                    content = f.read()
                    hashes['sha256'] = hashlib.sha256(content).hexdigest()
                    hashes['md5'] = hashlib.md5(content).hexdigest()
                    hashes['crc32'] = str(zlib.crc32(content))
                file_size = os.path.getsize(binary_path)
            except Exception as e:
                self.log(f"Error calculating hashes: {e}")

        # Architecture & Processor
        processor = ida_ida.inf_get_procname()
        if ida_pro.IDA_SDK_VERSION == 910:
            is_64 = ida_ida.idainfo_is_64bit()
            is_32 = ida_ida.idainfo_is_32bit()
        else:
            is_64 = ida_ida.inf_is_64bit()
            is_32 = ida_ida.inf_is_32bit_exactly()
            
        bitness = "64-bit" if is_64 else "32-bit" if is_32 else "16-bit"
        address_width = "64" if is_64 else "32" if is_32 else "16"
        endian = "Big endian" if ida_ida.inf_is_be() else "Little endian"

        # Compiler Info
        compiler_id = ida_ida.inf_get_cc_id()
        compiler_name = ida_typeinf.get_compiler_name(compiler_id)
        compiler_abbr = ida_typeinf.get_compiler_abbr(compiler_id)

        # Segments Stats
        segment_count = 0
        for seg_ea in idautils.Segments():
            segment_count += 1
        
        # Functions Stats
        function_count = 0
        lib_functions = 0
        user_functions = 0
        
        for func_ea in idautils.Functions():
            function_count += 1
            func_name = ida_funcs.get_func_name(func_ea)
            # Simple heuristic for user vs lib functions
            if func_name and (func_name.startswith('sub_') or not any(c in func_name for c in ['@', '.', '_imp_'])):
                user_functions += 1
            else:
                lib_functions += 1
        
        # Strings Stats
        string_count = 0
        for _ in idautils.Strings():
            string_count += 1
        
        # Imports & Exports Stats
        import_count = 0
        for i in range(ida_nalt.get_import_module_qty()):
            def cb(ea, name, ordinal):
                nonlocal import_count
                import_count += 1
                return True
            ida_nalt.enum_import_names(i, cb)
        
        export_count = 0
        try:
            for _ in idautils.Entries():
                export_count += 1
        except:
            try:
                export_count = ida_nalt.get_entry_qty()
            except:
                export_count = 0

        # Libraries List
        libraries = []
        for i in range(ida_nalt.get_import_module_qty()):
            name = ida_nalt.get_import_module_name(i)
            if name:
                libraries.append(name)

        # Construct Final JSON Structure
        final_meta = {
            "binary_name": binary_name,
            "arch": bitness,
            "processor": processor,
            "format": ida_loader.get_file_type_name(),
            "size": file_size,
            "image_base": hex(ida_nalt.get_imagebase()),
            "endian": endian,
            "address_width": address_width,
            "created_at": datetime.datetime.now().isoformat(),
            "counts": {
                "functions": function_count,
                "user_functions": user_functions,
                "library_functions": lib_functions,
                "imports": import_count,
                "exports": export_count,
                "strings": string_count,
                "segments": segment_count,
                "symbols": ida_name.get_nlist_size()
            },
            "hashes": hashes,
            "compiler": {
                "compiler_name": compiler_name,
                "compiler_abbr": compiler_abbr
            },
            "libraries": libraries
        }
        
        return final_meta

    def safe_int(self, val):
        if val is None: return None
        if val >= (1 << 63):
            val -= (1 << 64)
        return val

    def export_all(self):
        try:
            self.export_metadata()
            self.export_segments()
            self.export_sections()
            self.export_imports()
            self.export_exports()
            self.export_symbols()
            self.export_functions()
            self.export_pseudocode()
            self.export_disasm_chunks()
            self.export_data_items()
            self.export_strings()
            self.export_xrefs()
            self.export_call_edges()
            self.export_local_types()
        except Exception as e:
            self.log(f"Error during export: {e}")
            import traceback
            traceback.print_exc()
            raise e

    def export_metadata(self):
        self.timer.start_step("Metadata")
        self.log("Exporting metadata...")
        
        # Get the complete metadata dictionary
        final_meta = self.get_binary_info_dict()

        # Save as single JSON blob
        self.db.insert_metadata_json(json.dumps(final_meta))
        self.timer.end_step("Metadata")

    def export_symbols(self):
        self.timer.start_step("Symbols")
        self.log("Exporting symbols...")
        total_names = ida_name.get_nlist_size()
        tracker = ProgressTracker(total_names, self.log, "Symbols")
        
        data = []
        for i, (ea, name) in enumerate(idautils.Names()):
            tracker.update(i + 1)
            flags = ida_bytes.get_flags(ea)
            kind = "unknown"
            if ida_bytes.is_func(flags):
                kind = "function"
            elif ida_bytes.is_data(flags):
                kind = "data"
            elif ida_bytes.is_code(flags):
                kind = "label" # Code but not function start
            
            demangled = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM)
            
            # Size estimation
            size = 0
            if kind == "function":
                func = ida_funcs.get_func(ea)
                if func: size = func.size()
            elif kind == "data":
                size = ida_bytes.get_item_size(ea)
            
            data.append((name, demangled, kind, ea, size))
            
            if len(data) >= 1000:
                self.db.insert_symbols(data)
                data = []

        if data:
            self.db.insert_symbols(data)
        self.timer.end_step("Symbols")

    def export_functions(self):
        self.timer.start_step("Functions")
        self.log("Exporting functions...")
        total_funcs = ida_funcs.get_func_qty()
        tracker = ProgressTracker(total_funcs, self.log, "Functions")
        
        data = []
        rtree_data = []
        
        for i, ea in enumerate(idautils.Functions()):
            tracker.update(i + 1)
            func = ida_funcs.get_func(ea)
            name = ida_funcs.get_func_name(ea)
            demangled = None
            if name:
                demangled = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM)
            
            is_thunk = 1 if (func.flags & ida_funcs.FUNC_THUNK) else 0
            is_library = 1 if (func.flags & ida_funcs.FUNC_LIB) else 0
            
            data.append((ea, name, demangled, func.start_ea, func.end_ea, func.size(), is_thunk, is_library))
            rtree_data.append((ea, func.start_ea, func.end_ea))
            
            if len(data) >= 1000:
                self.db.insert_functions(data, rtree_data)
                data = []
                rtree_data = []

        if data:
            self.db.insert_functions(data, rtree_data)
        self.timer.end_step("Functions")

    def export_segments(self):
        self.timer.start_step("Segments")
        self.log("Exporting segments...")
        data = []
        for ea in idautils.Segments():
            seg = ida_segment.getseg(ea)
            name = ida_segment.get_segm_name(seg)
            perm = seg.perm
            perm_r = 1 if (perm & ida_segment.SEGPERM_READ) else 0
            perm_w = 1 if (perm & ida_segment.SEGPERM_WRITE) else 0
            perm_x = 1 if (perm & ida_segment.SEGPERM_EXEC) else 0
            
            seg_type = "UNKNOWN"
            if seg.type == ida_segment.SEG_CODE: seg_type = "CODE"
            elif seg.type == ida_segment.SEG_DATA: seg_type = "DATA"
            elif seg.type == ida_segment.SEG_BSS: seg_type = "BSS"
            elif seg.type == ida_segment.SEG_XTRN: seg_type = "EXTERN"
            
            file_offset = None 
            offset = ida_loader.get_fileregion_offset(ea)
            if offset != -1:
                file_offset = offset

            data.append((name, seg.start_ea, seg.end_ea, perm_r, perm_w, perm_x, file_offset, seg_type))
            
        self.db.insert_segments(data)
        self.timer.end_step("Segments")

    def export_sections(self):
        self.timer.start_step("Sections")
        self.log("Exporting sections...")
        data = []
        for ea in idautils.Segments():
            seg = ida_segment.getseg(ea)
            name = ida_segment.get_segm_name(seg)
            start_va = seg.start_ea
            end_va = seg.end_ea
            
            file_offset = None
            offset = ida_loader.get_fileregion_offset(ea)
            if offset != -1:
                file_offset = offset
            
            entropy = 0.0
            try:
                size = end_va - start_va
                if size > 0:
                    if size < 10 * 1024 * 1024:
                        content = ida_bytes.get_bytes(start_va, size)
                        entropy = calculate_entropy(content)
                    else:
                        content = ida_bytes.get_bytes(start_va, 1024*1024) # First 1MB
                        entropy = calculate_entropy(content)
            except Exception as e:
                self.log(f"Error calculating entropy for {name}: {e}")
                
            seg_type = "UNKNOWN"
            if seg.type == ida_segment.SEG_CODE: seg_type = "CODE"
            elif seg.type == ida_segment.SEG_DATA: seg_type = "DATA"
            elif seg.type == ida_segment.SEG_BSS: seg_type = "BSS"
            
            data.append((name, start_va, end_va, file_offset, entropy, seg_type))
            
        self.db.insert_sections(data)
        self.timer.end_step("Sections")

    def export_imports(self):
        self.timer.start_step("Imports")
        self.log("Exporting imports...")
        data = []
        
        import_modules = []
        for i in range(ida_nalt.get_import_module_qty()):
            name = ida_nalt.get_import_module_name(i)
            import_modules.append((i, name))
            
        for i, lib_name in import_modules:
            def callback(ea, name, ordinal):
                data.append((lib_name, name, ordinal, ea, None))
                return True
            ida_nalt.enum_import_names(i, callback)
            
        self.db.insert_imports(data)
        self.timer.end_step("Imports")

    def export_exports(self):
        self.timer.start_step("Exports")
        self.log("Exporting exports...")
        data = []
        for ordinal, ea, name, public_name in idautils.Entries():
            data.append((name if name else public_name, ordinal, ea, None))
            
        self.db.insert_exports(data)
        self.timer.end_step("Exports")

    def export_strings(self):
        self.timer.start_step("Strings")
        self.log("Exporting strings...")
        data = []
        s = idautils.Strings()
        for i in s:
            content = str(i)
            encoding = "ascii" 
            seg = ida_segment.getseg(i.ea)
            section_name = ida_segment.get_segm_name(seg) if seg else None
            
            data.append((i.ea, encoding, i.length, content, section_name))
            
            if len(data) >= 1000:
                self.db.insert_strings(data)
                data = []
                
        if data:
            self.db.insert_strings(data)
        self.timer.end_step("Strings")

    def export_pseudocode(self, function_list=None):
        self.timer.start_step("Pseudocode")
        if not ida_hexrays.init_hexrays_plugin():
            self.log("Hex-Rays decompiler not available, skipping pseudocode export.")
            self.timer.end_step("Pseudocode")
            return {
                "attempted": 0,
                "decompiled": 0,
                "failed": 0,
                "thunks": 0,
                "library": 0,
                "nofunc": 0,
                "none": 0,
                "min_ea": None,
                "max_ea": None,
                "top_errors": [],
                "hexrays_available": False,
            }

        self.log("Exporting pseudocode...")
        
        funcs_to_process = []
        if function_list:
            funcs_to_process = function_list
        else:
            # Get all functions
            funcs_to_process = [ea for ea in idautils.Functions()]
            
        total_funcs = len(funcs_to_process)
        min_ea = None
        max_ea = None
        if funcs_to_process:
            try:
                min_ea = int(min(funcs_to_process))
                max_ea = int(max(funcs_to_process))
            except Exception:
                min_ea = None
                max_ea = None

        start_time = time.time()
        next_log_time = start_time
        decompiled = 0
        failed = 0
        thunks = 0
        library = 0
        nofunc = 0
        none_results = 0
        error_counts = {}
        error_order = []
        last_name = ""
        last_ea = None

        data = []
        for i, ea in enumerate(funcs_to_process):
            func = None
            try:
                func = ida_funcs.get_func(ea)
            except Exception:
                func = None

            if not func:
                nofunc += 1
                failed += 1
                key = "no_func"
                error_counts[key] = error_counts.get(key, 0) + 1
                if key not in error_order:
                    error_order.append(key)
                continue

            try:
                if func.flags & ida_funcs.FUNC_THUNK:
                    thunks += 1
                if func.flags & ida_funcs.FUNC_LIB:
                    library += 1
            except Exception:
                pass

            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    content = str(cfunc)
                    data.append((ea, content))
                    decompiled += 1
                else:
                    failed += 1
                    none_results += 1
                    key = "decompile_returned_none"
                    error_counts[key] = error_counts.get(key, 0) + 1
                    if key not in error_order:
                        error_order.append(key)
            except Exception as e:
                failed += 1
                key = f"{type(e).__name__}: {str(e)}"
                error_counts[key] = error_counts.get(key, 0) + 1
                if key not in error_order:
                    error_order.append(key)

            last_ea = ea
            try:
                last_name = ida_funcs.get_func_name(ea) or ""
            except Exception:
                last_name = ""

            now = time.time()
            if now >= next_log_time or (i + 1) >= total_funcs:
                elapsed = now - start_time
                if elapsed < 0.001:
                    elapsed = 0.001
                rate = (i + 1) / elapsed
                remaining = total_funcs - (i + 1)
                eta_seconds = remaining / rate if rate > 0 else 0
                percent = ((i + 1) / total_funcs * 100.0) if total_funcs else 100.0
                where = f"{last_name}@{hex(last_ea)}" if last_ea is not None else ""
                self.log(
                    f"Pseudocode: {percent:5.1f}% ({i+1}/{total_funcs}) ok={decompiled} fail={failed} rate={rate:.2f}/s eta={int(eta_seconds)}s {where}".rstrip()
                )
                next_log_time = now + 2.0
            
            if len(data) >= 100:
                self.db.insert_pseudocode(data)
                data = []
        
        if data:
            self.db.insert_pseudocode(data)
        self.timer.end_step("Pseudocode")

        top_errors = []
        for key in error_order:
            if key in error_counts:
                top_errors.append({"error": key, "count": int(error_counts[key])})
            if len(top_errors) >= 5:
                break
        return {
            "attempted": total_funcs,
            "decompiled": decompiled,
            "failed": failed,
            "thunks": thunks,
            "library": library,
            "nofunc": nofunc,
            "none": none_results,
            "min_ea": min_ea,
            "max_ea": max_ea,
            "top_errors": top_errors,
            "hexrays_available": True,
        }

    def dump_function_list(self, output_path):
        self.log(f"Dumping function list to {output_path}...")
        funcs = [ea for ea in idautils.Functions()]
        with open(output_path, 'w') as f:
            json.dump(funcs, f)
        self.log(f"Dumped {len(funcs)} functions.")

    def export_disasm_chunks(self):
        self.timer.start_step("DisasmChunks")
        self.log("Exporting disasm chunks...")
        
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        total_range = max_ea - min_ea
        if total_range <= 0: total_range = 1
        tracker = ProgressTracker(total_range, self.log, "Disasm Chunks")

        CHUNK_SIZE_LINES = 100
        data = []
        
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg: continue
            
            current_chunk_lines = []
            current_chunk_start = None
            current_chunk_end = None
            
            for head in idautils.Heads(seg.start_ea, seg.end_ea):
                tracker.update(head - min_ea)
                if current_chunk_start is None:
                    current_chunk_start = head
                
                disasm_text = idc.generate_disasm_line(head, 0)
                if disasm_text:
                    current_chunk_lines.append(f"{hex(head)}: {disasm_text}")
                
                current_chunk_end = head + ida_bytes.get_item_size(head)
                
                if len(current_chunk_lines) >= CHUNK_SIZE_LINES:
                    content = "\n".join(current_chunk_lines)
                    data.append((current_chunk_start, current_chunk_end, content))
                    current_chunk_lines = []
                    current_chunk_start = None
            
            if current_chunk_lines:
                content = "\n".join(current_chunk_lines)
                data.append((current_chunk_start, current_chunk_end, content))

            if len(data) >= 100:
                 self.db.insert_disasm_chunks(data)
                 data = []

        if data:
            self.db.insert_disasm_chunks(data)
        self.timer.end_step("DisasmChunks")

    def export_data_items(self):
        self.timer.start_step("DataItems")
        self.log("Exporting data items...")
        
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        total_range = max_ea - min_ea
        if total_range <= 0: total_range = 1
        tracker = ProgressTracker(total_range, self.log, "Data Items")
        
        data = []
        for ea in idautils.Heads():
            tracker.update(ea - min_ea)
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_data(flags):
                size = ida_bytes.get_item_size(ea)
                
                kind = "byte"
                type_name = "unknown"
                repr_str = ""
                target_va = None
                
                if ida_bytes.is_strlit(flags):
                    kind = "string"
                    repr_str = str(ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C))
                elif ida_bytes.is_off0(flags) or ida_bytes.is_off1(flags):
                     kind = "offset"
                     xrefs = idautils.DataRefsFrom(ea)
                     for x in xrefs:
                         target_va = x
                         break
                else:
                    width = ida_bytes.get_item_size(ea)
                    if width == 1: kind = "byte"
                    elif width == 2: kind = "word"
                    elif width == 4: kind = "dword"
                    elif width == 8: kind = "qword"
                    else: kind = "array/struct"
                
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, ea):
                    type_name = str(tif)
                
                if not repr_str:
                    repr_str = idc.generate_disasm_line(ea, 0)

                data.append((ea, size, kind, type_name, repr_str, target_va))

            if len(data) >= 1000:
                self.db.insert_data_items(data)
                data = []

        if data:
            self.db.insert_data_items(data)
        self.timer.end_step("DataItems")

    def export_xrefs(self):
        self.timer.start_step("Xrefs")
        self.log("Exporting xrefs...")
        
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        total_range = max_ea - min_ea
        if total_range <= 0: total_range = 1
        tracker = ProgressTracker(total_range, self.log, "Xrefs")
        
        data = []
        for ea in idautils.Heads():
            tracker.update(ea - min_ea)
            for xref in idautils.XrefsFrom(ea, 0):
                if not ida_segment.getseg(xref.to):
                    continue

                xref_type_str = "unknown"
                t = xref.type
                if t == ida_xref.fl_CF or t == ida_xref.fl_CN: xref_type_str = "call"
                elif t == ida_xref.fl_JF or t == ida_xref.fl_JN: xref_type_str = "jmp"
                elif t == ida_xref.dr_R: xref_type_str = "data_read"
                elif t == ida_xref.dr_W: xref_type_str = "data_write"
                elif t == ida_xref.dr_O: xref_type_str = "offset"
                
                from_func = ida_funcs.get_func(xref.frm)
                to_func = ida_funcs.get_func(xref.to)
                
                from_func_va = from_func.start_ea if from_func else None
                to_func_va = to_func.start_ea if to_func else None
                
                data.append((self.safe_int(xref.frm), self.safe_int(xref.to), self.safe_int(from_func_va), self.safe_int(to_func_va), xref_type_str, 0))
                
            if len(data) >= 1000:
                self.db.insert_xrefs(data)
                data = []

        if data:
            self.db.insert_xrefs(data)
        self.timer.end_step("Xrefs")
    
    def export_call_edges(self):
        self.timer.start_step("CallEdges")
        self.log("Exporting call edges...")
        data = []
        
        for ea in idautils.Functions():
            func = ida_funcs.get_func(ea)
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for xref in idautils.XrefsFrom(head, ida_xref.XREF_FAR):
                    if xref.iscode: 
                        t = xref.type
                        if t == ida_xref.fl_CF or t == ida_xref.fl_CN:
                             callee_func = ida_funcs.get_func(xref.to)
                             if callee_func:
                                 data.append((self.safe_int(func.start_ea), self.safe_int(callee_func.start_ea), self.safe_int(head), "direct"))
        
        if data:
             self.db.insert_call_edges(data)
        self.timer.end_step("CallEdges")

    def export_local_types(self):
        self.timer.start_step("LocalTypes")
        self.log("Exporting local types...")
        
        content_lines = []
        try:
            til = ida_typeinf.get_idati()
            if til:
                qty = 0
                if hasattr(ida_typeinf, 'get_ordinal_count'):
                    qty = ida_typeinf.get_ordinal_count(til)
                elif hasattr(ida_typeinf, 'get_ordinal_qty'):
                    qty = ida_typeinf.get_ordinal_qty(til)
                
                flags = 41
                
                for i in range(1, qty):
                    name = ida_typeinf.get_numbered_type_name(til, i)
                    if not name:
                        continue
                    
                    tinfo = ida_typeinf.tinfo_t()
                    if tinfo.get_numbered_type(til, i):
                        defn = tinfo._print(name, flags)
                        if defn:
                            content_lines.append(f"// {name}")
                            content_lines.append(defn)
                            content_lines.append("") 

        except Exception as e:
            self.log(f"Error iterating local types: {e}")

        full_content = "\n".join(content_lines)
        
        if full_content:
            self.db.insert_local_types("default", full_content)
        else:
             self.log("No local types found.")
        self.timer.end_step("LocalTypes")
