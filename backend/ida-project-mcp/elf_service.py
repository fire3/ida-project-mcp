import os
import hashlib
from dataclasses import dataclass

@dataclass(frozen=True)
class ElfIdentity:
    elf_class: int
    elf_data: int
    e_machine: int

def _read_exact(f, size):
    b = f.read(size)
    if len(b) != size:
        raise EOFError(f"short read: want={size} got={len(b)}")
    return b

def _u16(b, off, endian):
    if endian == 1:
        return int.from_bytes(b[off:off + 2], "little")
    if endian == 2:
        return int.from_bytes(b[off:off + 2], "big")
    raise ValueError("invalid endian")

def _u32(b, off, endian):
    if endian == 1:
        return int.from_bytes(b[off:off + 4], "little")
    if endian == 2:
        return int.from_bytes(b[off:off + 4], "big")
    raise ValueError("invalid endian")

def _u64(b, off, endian):
    if endian == 1:
        return int.from_bytes(b[off:off + 8], "little")
    if endian == 2:
        return int.from_bytes(b[off:off + 8], "big")
    raise ValueError("invalid endian")

def _parse_elf_header_fields(hdr, elf_class, elf_data):
    if elf_class == 1:
        e_phoff = _u32(hdr, 28, elf_data)
        e_phentsize = _u16(hdr, 42, elf_data)
        e_phnum = _u16(hdr, 44, elf_data)
        return e_phoff, e_phentsize, e_phnum
    e_phoff = _u64(hdr, 32, elf_data)
    e_phentsize = _u16(hdr, 54, elf_data)
    e_phnum = _u16(hdr, 56, elf_data)
    return e_phoff, e_phentsize, e_phnum

def _parse_phdr(buf, elf_class, elf_data):
    if elf_class == 1:
        p_type = _u32(buf, 0, elf_data)
        p_offset = _u32(buf, 4, elf_data)
        p_vaddr = _u32(buf, 8, elf_data)
        p_filesz = _u32(buf, 16, elf_data)
        p_memsz = _u32(buf, 20, elf_data)
        return {
            "p_type": p_type,
            "p_offset": p_offset,
            "p_vaddr": p_vaddr,
            "p_filesz": p_filesz,
            "p_memsz": p_memsz,
        }
    p_type = _u32(buf, 0, elf_data)
    p_offset = _u64(buf, 8, elf_data)
    p_vaddr = _u64(buf, 16, elf_data)
    p_filesz = _u64(buf, 32, elf_data)
    p_memsz = _u64(buf, 40, elf_data)
    return {
        "p_type": p_type,
        "p_offset": p_offset,
        "p_vaddr": p_vaddr,
        "p_filesz": p_filesz,
        "p_memsz": p_memsz,
    }

def _vaddr_to_offset(phdrs, vaddr):
    for ph in phdrs:
        if ph["p_type"] != 1:
            continue
        start = ph["p_vaddr"]
        end = start + ph["p_memsz"]
        if start <= vaddr < end:
            return ph["p_offset"] + (vaddr - start)
    return None

class ElfService:
    """
    Service for analyzing ELF binaries and resolving dependencies.
    """

    @staticmethod
    def read_elf_identity(path):
        """
        Reads the ELF identity (class, data, machine) from the file.
        Returns ElfIdentity object or None if not an ELF file.
        """
        try:
            with open(path, "rb") as f:
                ident = _read_exact(f, 64)
            if ident[0:4] != b"\x7fELF":
                return None
            elf_class = ident[4]
            elf_data = ident[5]
            if elf_class not in (1, 2):
                return None
            e_machine = _u16(ident, 18, elf_data)
            return ElfIdentity(elf_class=elf_class, elf_data=elf_data, e_machine=e_machine)
        except Exception:
            return None

    @staticmethod
    def read_elf_needed(path):
        """
        Reads DT_NEEDED entries from the dynamic section of an ELF file.
        Returns a list of shared library names needed by the binary.
        """
        try:
            with open(path, "rb") as f:
                hdr = _read_exact(f, 64)
                if hdr[0:4] != b"\x7fELF":
                    return []
                elf_class = hdr[4]
                elf_data = hdr[5]
                if elf_class not in (1, 2) or elf_data not in (1, 2):
                    return []
                e_phoff, e_phentsize, e_phnum = _parse_elf_header_fields(hdr, elf_class, elf_data)
                if e_phoff == 0 or e_phnum == 0 or e_phentsize == 0:
                    return []
                phdrs = []
                f.seek(e_phoff)
                for _ in range(e_phnum):
                    ph_buf = _read_exact(f, e_phentsize)
                    phdrs.append(_parse_phdr(ph_buf, elf_class, elf_data))

                dyn = None
                for ph in phdrs:
                    if ph["p_type"] == 2:
                        dyn = ph
                        break
                if not dyn or dyn["p_filesz"] == 0:
                    return []

                f.seek(dyn["p_offset"])
                dyn_bytes = _read_exact(f, dyn["p_filesz"])

                dt_needed = []
                dt_strtab = None
                dt_strsz = None
                idx = 0
                if elf_class == 1:
                    ent_size = 8
                    while idx + ent_size <= len(dyn_bytes):
                        tag = int.from_bytes(dyn_bytes[idx:idx + 4], "little" if elf_data == 1 else "big", signed=True)
                        val = int.from_bytes(dyn_bytes[idx + 4:idx + 8], "little" if elf_data == 1 else "big", signed=False)
                        idx += ent_size
                        if tag == 0:
                            break
                        if tag == 1:
                            dt_needed.append(val)
                        elif tag == 5:
                            dt_strtab = val
                        elif tag == 10:
                            dt_strsz = val
                else:
                    ent_size = 16
                    while idx + ent_size <= len(dyn_bytes):
                        tag = int.from_bytes(dyn_bytes[idx:idx + 8], "little" if elf_data == 1 else "big", signed=True)
                        val = int.from_bytes(dyn_bytes[idx + 8:idx + 16], "little" if elf_data == 1 else "big", signed=False)
                        idx += ent_size
                        if tag == 0:
                            break
                        if tag == 1:
                            dt_needed.append(val)
                        elif tag == 5:
                            dt_strtab = val
                        elif tag == 10:
                            dt_strsz = val

                if not dt_needed or dt_strtab is None:
                    return []
                strtab_off = _vaddr_to_offset(phdrs, dt_strtab)
                if strtab_off is None:
                    return []

                f.seek(strtab_off)
                if dt_strsz is not None and dt_strsz > 0:
                    strtab = _read_exact(f, dt_strsz)
                else:
                    strtab = f.read(1024 * 1024)

            needed_names = []
            for off in dt_needed:
                if off >= len(strtab):
                    continue
                end = strtab.find(b"\x00", off)
                if end == -1:
                    continue
                try:
                    s = strtab[off:end].decode("utf-8", errors="replace")
                except Exception:
                    continue
                if s:
                    needed_names.append(s)
            return needed_names
        except Exception:
            return []

    @staticmethod
    def build_basename_index(scan_dir):
        """
        Scans a directory recursively and builds a mapping of basename -> [full_paths].
        """
        mapping = {}
        for root, _, files in os.walk(scan_dir):
            for fn in files:
                full = os.path.join(root, fn)
                base = os.path.basename(full)
                mapping.setdefault(base, []).append(full)
        return mapping

    @classmethod
    def resolve_recursive_dependencies(cls, scan_dir, target_path):
        """
        Recursively resolves dependencies for a target binary within a scan directory.
        Returns a list of dicts: [{"name": "libfoo.so", "path": "/path/to/libfoo.so"}, ...]
        """
        scan_dir = os.path.abspath(scan_dir)
        target_path = os.path.abspath(target_path)
        idx = cls.build_basename_index(scan_dir)

        resolved_map = {}  # name -> path
        visited_paths = set()
        queue = []

        # Start with target
        visited_paths.add(target_path)
        queue.append(target_path)

        while queue:
            curr_path = queue.pop(0)
            curr_id = cls.read_elf_identity(curr_path)
            needed = cls.read_elf_needed(curr_path)

            for name in needed:
                if name in resolved_map:
                    continue

                candidates = idx.get(name, [])
                best = None
                if curr_id:
                    for c in candidates:
                        cid = cls.read_elf_identity(c)
                        if cid and cid == curr_id:
                            best = c
                            break
                if not best and candidates:
                    best = candidates[0]

                resolved_map[name] = best
                if best and best not in visited_paths:
                    visited_paths.add(best)
                    queue.append(best)

        return [{"name": k, "path": v} for k, v in resolved_map.items()]
