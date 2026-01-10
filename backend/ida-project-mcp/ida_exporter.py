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

def get_binary_info_dict():
    """Extract basic information about the loaded binary in IDA and return as a dictionary.
    
    Returns:
        dict: A dictionary containing the following structure:
        {
            "basic_info": {
                "binary_name": str,          # 二进制文件名
                "full_path": str,            # 完整文件路径
                "file_size": int,            # 文件大小（字节）
                "processor": str,            # 处理器类型
                "architecture": str,         # 架构（32位/64位）
                "entry_point": int,          # 入口点地址
                "image_base": int           # 镜像基址
            },
            "segments": {
                "segments_list": [           # 段信息列表
                    {
                        "name": str,         # 段名
                        "start_address": int,# 起始地址
                        "end_address": int,  # 结束地址
                        "size": int,         # 段大小
                        "permissions": str   # 权限（RWX组合）
                    },
                    ...
                ],
                "total_segments": int,       # 总段数
                "total_segment_size": int    # 总段大小
            },
            "functions": {
                "total_functions": int,      # 总函数数
                "user_functions": int,       # 用户函数数
                "library_functions": int,    # 库函数数
                "average_function_size": int # 平均函数大小
            },
            "strings": {
                "total_strings": int         # 总字符串数
            },
            "imports_exports": {
                "imported_functions": int,   # 导入函数数
                "exported_functions": int    # 导出函数数
            },
            "additional_info": {
                "file_type": str,           # 文件类型
                "compiler_name": str,       # 编译器名称
                "compiler_abbr": str        # 编译器缩写
            }
        }
    """
    result = {
        "basic_info": {},
        "segments": {
            "segments_list": []
        },
        "functions": {},
        "strings": {},
        "imports_exports": {},
        "additional_info": {}
    }
    
    # Get binary path and name
    binary_path = ida_nalt.get_input_file_path()
    binary_name = os.path.basename(binary_path)
    
    result["basic_info"]["binary_name"] = binary_name
    result["basic_info"]["full_path"] = binary_path
    
    # Get file size
    try:
        file_size = os.path.getsize(binary_path)
        result["basic_info"]["file_size"] = file_size
    except:
        result["basic_info"]["file_size"] = None
    
    # Get architecture and processor info
    processor = ida_ida.inf_get_procname()
    if ida_pro.IDA_SDK_VERSION == 910:
        bitness = "64-bit" if ida_ida.idainfo_is_64bit() else "32-bit" if ida_ida.idainfo_is_32bit() else "16-bit"
    else:
        bitness = "64-bit" if ida_ida.inf_is_64bit() else "32-bit" if ida_ida.inf_is_32bit_exactly() else "16-bit"
    
    result["basic_info"]["processor"] = processor
    result["basic_info"]["architecture"] = bitness
    
    # Get entry point and image base
    result["basic_info"]["entry_point"] = ida_ida.inf_get_start_ea()
    result["basic_info"]["image_base"] = ida_nalt.get_imagebase()
    
    # Get segments information
    segment_count = 0
    total_segment_size = 0
    
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg:
            segment_count += 1
            seg_info = {
                "name": ida_segment.get_segm_name(seg),
                "start_address": seg.start_ea,
                "end_address": seg.end_ea,
                "size": seg.end_ea - seg.start_ea,
                "permissions": ""
            }
            
            # Get segment permissions
            if seg.perm & ida_segment.SEGPERM_READ:
                seg_info["permissions"] += "R"
            if seg.perm & ida_segment.SEGPERM_WRITE:
                seg_info["permissions"] += "W"
            if seg.perm & ida_segment.SEGPERM_EXEC:
                seg_info["permissions"] += "X"
            
            total_segment_size += seg_info["size"]
            result["segments"]["segments_list"].append(seg_info)
    
    result["segments"]["total_segments"] = segment_count
    result["segments"]["total_segment_size"] = total_segment_size
    
    # Get function information
    function_count = 0
    total_func_size = 0
    lib_functions = 0
    user_functions = 0
    
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if func:
            function_count += 1
            func_size = func.end_ea - func.start_ea
            total_func_size += func_size
            
            func_name = ida_funcs.get_func_name(func_ea)
            if func_name and (func_name.startswith('sub_') or not any(c in func_name for c in ['@', '.', '_imp_'])):
                user_functions += 1
            else:
                lib_functions += 1
    
    result["functions"]["total_functions"] = function_count
    result["functions"]["user_functions"] = user_functions
    result["functions"]["library_functions"] = lib_functions
    result["functions"]["average_function_size"] = total_func_size // function_count if function_count > 0 else 0
    
    # Get strings information
    string_count = 0
    for string in idautils.Strings():
        string_count += 1
    
    result["strings"]["total_strings"] = string_count
    
    # Get imports and exports
    import_count = 0
    for i in range(ida_nalt.get_import_module_qty()):
        name = ida_nalt.get_import_module_name(i)
        if not name:
            break
        
        def cb(ea, name, ordinal):
            nonlocal import_count
            import_count += 1
            return True
        
        ida_nalt.enum_import_names(i, cb)
    
    export_count = 0
    try:
        for ordinal in range(ida_entry.get_entry_qty()):
            entry_ea = ida_entry.get_entry(ordinal)
            if entry_ea != ida_ida.BADADDR:
                export_count += 1
    except:
        try:
            export_count = ida_nalt.get_entry_qty()
        except:
            export_count = 0
    
    result["imports_exports"]["imported_functions"] = import_count
    result["imports_exports"]["exported_functions"] = export_count
    
    # Additional file information
    result["additional_info"]["file_type"] = ida_loader.get_file_type_name()
    
    compiler_id = ida_ida.inf_get_cc_id()
    result["additional_info"]["compiler_name"] = ida_typeinf.get_compiler_name(compiler_id)
    result["additional_info"]["compiler_abbr"] = ida_typeinf.get_compiler_abbr(compiler_id)
    
    return result

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
             meta['size'] = os.path.getsize(input_path)
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
        meta['info'] = get_binary_info_dict()
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
