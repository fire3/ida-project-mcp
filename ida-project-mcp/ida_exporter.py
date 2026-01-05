import sys
import os
import hashlib
import zlib
import json
import time

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
        meta = {}
        
        input_path = None
        if self.input_file:
            input_path = self.input_file
        else:
             input_path = ida_nalt.get_input_file_path()

        if input_path and os.path.exists(input_path):
             with open(input_path, 'rb') as f:
                content = f.read()
                meta['sha256'] = hashlib.sha256(content).hexdigest()
                meta['md5'] = hashlib.md5(content).hexdigest()
                meta['crc32'] = str(zlib.crc32(content))
        else:
             self.log(f"Warning: Input file path not found or invalid: {input_path}")
             meta['sha256'] = ""
             meta['md5'] = ""
             meta['crc32'] = ""
        
        meta['file_name'] = ida_nalt.get_root_filename()
        meta['format'] = ida_loader.get_file_type_name()
        meta['image_base'] = hex(ida_nalt.get_imagebase())
        
        meta['processor'] = ida_ida.inf_get_procname()
        
        if ida_ida.inf_is_64bit():
            meta['address_width'] = '64'
        elif ida_ida.inf_is_32bit_exactly():
            meta['address_width'] = '32'
        else:
            meta['address_width'] = '16'
            
        if ida_ida.inf_is_be():
            meta['endian'] = 'Big endian'
        else:
            meta['endian'] = 'Little endian'

        meta['created_at'] = str(int(time.time()))
        
        # Libraries
        libs = []
        for i in range(ida_nalt.get_import_module_qty()):
            libs.append(ida_nalt.get_import_module_name(i))
        meta['libraries'] = json.dumps(libs)

        self.db.insert_metadata(meta)
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

    def export_pseudocode(self):
        self.timer.start_step("Pseudocode")
        if not ida_hexrays.init_hexrays_plugin():
            self.log("Hex-Rays decompiler not available, skipping pseudocode export.")
            self.timer.end_step("Pseudocode")
            return

        self.log("Exporting pseudocode...")
        total_funcs = ida_funcs.get_func_qty()
        tracker = ProgressTracker(total_funcs, self.log, "Pseudocode")

        data = []
        for i, ea in enumerate(idautils.Functions()):
            tracker.update(i + 1)
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    content = str(cfunc)
                    data.append((ea, content))
            except Exception as e:
                pass
            
            if len(data) >= 100:
                self.db.insert_pseudocode(data)
                data = []
        
        if data:
            self.db.insert_pseudocode(data)
        self.timer.end_step("Pseudocode")

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
