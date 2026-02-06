import sys
import os
import io
import glob
import struct
import zipfile
import olefile
import re
import json
import xml.etree.ElementTree as ET

# Import rtfobj for RTF parsing
try:
    from oletools import rtfobj
    RTF_SUPPORT = True
except ImportError:
    RTF_SUPPORT = False
    print("[!] Warning: oletools.rtfobj not found. RTF support disabled (pip install oletools).")

# Import MSO/ActiveMime parsing
try:
    from oletools.olevba import is_mso_file, mso_file_extract
    import zlib
    MSO_SUPPORT = True
except ImportError:
    MSO_SUPPORT = False
    print("[!] Warning: oletools.olevba MSO functions not found. MSO support disabled (pip install oletools).")

# --- CONFIGURATION & CONSTANTS ---
SHELL_EXPLORER_CLSID_STR = "{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}"
SHELL_EXPLORER_CLSID_BYTES = b'\xC3\x2A\xB2\xEA\xC1\x30\xCF\x11\xA7\xEB\x00\x00\xC0\x5B\xAE\x0B'
LNK_HEADER_SIG = b'\x4c\x00\x00\x00'
LNK_CLSID_BYTES = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'

# Regex for "Shell.Explorer.1" (ASCII or Wide, Case Insensitive)
REGEX_SHELL_EXPLORER = re.compile(
    rb"s\x00?h\x00?e\x00?l\x00?l\x00?\.\x00?e\x00?x\x00?p\x00?l\x00?o\x00?r\x00?e\x00?r\x00?\.\x00?1", 
    re.IGNORECASE
)

class ShellExplorerHunter:
    def __init__(self, knownfolders_path=None, json_out=None):
        self.json_results = []
        self.knownfolders_path = knownfolders_path
        self.json_out = json_out
        pass

    def scan_path(self, path_arg):
        """Resolves argument to file list and scans."""
        if os.path.isdir(path_arg):
            files = [os.path.join(path_arg, f) for f in os.listdir(path_arg) 
                     if os.path.isfile(os.path.join(path_arg, f))]
        else:
            files = glob.glob(path_arg)

        if not files:
            print(f"[-] No files found matching: {path_arg}")
            return

        print(f"[*] Scanning {len(files)} file(s)...")
        print("="*80)

        for filepath in files:
            self.process_file(filepath)
        # Write JSON report if we collected any Shell.Explorer.1 IDLISTs
        if self.json_results:
            if self.json_out:
                out_path = self.json_out
            else:
                if not os.path.exists("dumps"):
                    os.makedirs("dumps")
                out_path = os.path.join("dumps", "shell_explorer_idlists.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(self.json_results, f, indent=2)
            print(f"[+] JSON report written: {out_path}")

    def process_file(self, filepath):
        self.current_file = os.path.basename(filepath)
        filename = os.path.basename(filepath)

        # 1. Format Detection
        is_zip = zipfile.is_zipfile(filepath)
        is_ole = olefile.isOleFile(filepath)

        # Check for MSO/ActiveMime files
        is_mso = False
        if MSO_SUPPORT:
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                    if is_mso_file(data):
                        is_mso = True
            except: pass

        # Relaxed RTF Check: Just look for '{\rt'
        is_rtf = False
        try:
            with open(filepath, 'rb') as f:
                header = f.read(4) # Read first 4 bytes
                if header.startswith(b'{\\rt'):
                    is_rtf = True
        except: pass

        if not is_zip and not is_ole and not is_rtf and not is_mso:
            return

        print(f"[*] Analyzing: {filename}")
        try:
            if is_mso:
                # MSO takes priority - extract and process embedded OLE
                with open(filepath, 'rb') as f:
                    self.handle_mso(f.read(), os.path.basename(filepath))
            elif is_ole:
                # Pass path to legacy handler
                force_scan = self.detect_shell_explorer_raw(filepath)
                self.handle_legacy(filepath, force_scan=force_scan)
            elif is_zip:
                self.handle_ooxml(filepath)
            elif is_rtf and RTF_SUPPORT:
                self.handle_rtf(filepath)
        except Exception as e:
            print(f"    [!] Error: {e}")
        print("-" * 40)

    # =========================================================================
    # RTF HANDLER
    # =========================================================================
    def handle_rtf(self, filepath):
        print("    [i] Processing as RTF...")
        try:
            # rtfobj handles hex decoding and obfuscation
            parser = rtfobj.RtfObjParser(open(filepath, 'rb').read())
            parser.parse()
            
            if not parser.objects:
                print("    [.] No OLE objects found in RTF.")
                return

            for i, obj in enumerate(parser.objects):
                # Dump basic rtfobj metadata (class/CLSID come from RTF object headers)
                class_name = getattr(obj, "class_name", b"")
                clsid = getattr(obj, "clsid", "")
                if class_name or clsid:
                    cn_disp = class_name.decode(errors="ignore") if isinstance(class_name, (bytes, bytearray)) else str(class_name)
                    print(f"    [i] RTF Object #{i} class_name={cn_disp!r} clsid={clsid!r}")
                # If the RTF object itself advertises Shell.Explorer.1, force scan for LNKs
                obj_match = False
                if isinstance(class_name, (bytes, bytearray)) and b"shell.explorer.1" in class_name.lower():
                    obj_match = True
                if isinstance(class_name, str) and "shell.explorer.1" in class_name.lower():
                    obj_match = True
                if isinstance(clsid, str) and clsid.strip("{}").upper() == SHELL_EXPLORER_CLSID_STR.strip("{}").upper():
                    obj_match = True

                if obj.oledata:
                    # Treat extracted data as a file stream
                    blob_stream = io.BytesIO(obj.oledata)
                    
                    if olefile.isOleFile(blob_stream):
                        print(f"    [+] RTF Object #{i}: Detected OLE Compound File.")
                        if obj_match:
                            print(f"    [+] RTF Object #{i}: Shell.Explorer.1 metadata match, forcing stream scan.")
                        self.handle_legacy(blob_stream, source_desc=f"RTF_Obj_{i}", force_scan=obj_match)
                    else:
                        # Raw data fallback
                        if SHELL_EXPLORER_CLSID_BYTES in obj.oledata or REGEX_SHELL_EXPLORER.search(obj.oledata):
                             print(f"    [+] Found Shell.Explorer.1 signature in raw RTF object #{i}")
                             self.carve_stream(obj.oledata, f"RTF_Raw_Obj_{i}")
        except Exception as e:
            print(f"    [!] RTF Parsing Error: {e}")

    # =========================================================================
    # MSO/ACTIVEMIME HANDLER
    # =========================================================================
    def handle_mso(self, data, source_desc="MSO_File"):
        """Process MSO/ActiveMime files (oledata.mso, editdata.mso)"""
        print("    [i] Processing as MSO/ActiveMime...")
        try:
            # Extract the compressed OLE data
            ole_data = mso_file_extract(data)
            print(f"    [+] Extracted {len(ole_data)} bytes from MSO file")

            # Check if extracted data is an OLE file
            ole_stream = io.BytesIO(ole_data)
            if olefile.isOleFile(ole_stream):
                print(f"    [+] Detected OLE Compound File in extracted MSO data")
                # Force scan since MSO files are often used for evasion
                self.handle_legacy(ole_stream, source_desc=f"MSO_{source_desc}", force_scan=True)
            else:
                # Fallback: raw scan for Shell.Explorer.1 signatures
                print(f"    [i] Extracted data is not OLE, scanning for Shell.Explorer.1 signatures...")
                if SHELL_EXPLORER_CLSID_BYTES in ole_data or REGEX_SHELL_EXPLORER.search(ole_data):
                    print(f"    [+] Found Shell.Explorer.1 signature in raw MSO data")
                    self.carve_stream(ole_data, f"MSO_Raw_{source_desc}")
        except Exception as e:
            print(f"    [!] MSO Extraction Error: {e}")

    def detect_shell_explorer_raw(self, filepath):
        # Quick raw scan to decide whether to force-scan all OLE streams
        try:
            data = open(filepath, "rb").read()
        except Exception:
            return False
        if SHELL_EXPLORER_CLSID_BYTES in data:
            return True
        if REGEX_SHELL_EXPLORER.search(data):
            return True
        if LNK_CLSID_BYTES in data or LNK_HEADER_SIG in data:
            return True
        return False

    # =========================================================================
    # OOXML HANDLER (.docx, .xlsx)
    # =========================================================================
    def handle_ooxml(self, filepath):
        with zipfile.ZipFile(filepath, 'r') as z:
            ax_xmls = [f for f in z.namelist() if 'activeX' in f and f.endswith('.xml')]

            for ax_xml_path in ax_xmls:
                try:
                    xml_data = z.read(ax_xml_path)
                    if SHELL_EXPLORER_CLSID_STR.encode('utf-8') in xml_data.upper():
                        print(f"    [+] Found Shell.Explorer.1 definition: {ax_xml_path}")

                        folder = os.path.dirname(ax_xml_path)
                        filename = os.path.basename(ax_xml_path)
                        rels_path = f"{folder}/_rels/{filename}.rels"

                        target_bin = None
                        if rels_path in z.namelist():
                            target_bin = self.parse_rels_for_bin(z.read(rels_path))

                        if target_bin:
                            full_bin_path = f"{folder}/{target_bin}"
                            if full_bin_path not in z.namelist():
                                full_bin_path = next((n for n in z.namelist() if n.endswith(target_bin)), None)
                            if full_bin_path:
                                self.carve_stream(z.read(full_bin_path), full_bin_path)
                except: pass

            # Parse OLE object definitions from document XML files
            doc_xmls = [f for f in z.namelist()
                       if (f.endswith('/document.xml') or f.endswith('/workbook.xml') or
                           f.endswith('/presentation.xml')) and not f.startswith('_')]

            for doc_xml_path in doc_xmls:
                try:
                    doc_data = z.read(doc_xml_path).decode('utf-8', errors='ignore')
                    folder = os.path.dirname(doc_xml_path)

                    # Find OLEObject tags with Shell.Explorer.1 ProgID
                    ole_objects = re.findall(r'<[^:]+:OLEObject[^>]+>', doc_data, re.IGNORECASE)

                    for ole_obj in ole_objects:
                        # Extract ProgID
                        prog_id_match = re.search(r'ProgID=["\']([^"\']+)["\']', ole_obj, re.IGNORECASE)
                        # Extract CLSID
                        clsid_match = re.search(r'classid=["\']([^"\']+)["\']', ole_obj, re.IGNORECASE)
                        # Extract relationship ID
                        rid_match = re.search(r'r:id=["\']([^"\']+)["\']', ole_obj, re.IGNORECASE)

                        prog_id = prog_id_match.group(1) if prog_id_match else None
                        clsid = clsid_match.group(1) if clsid_match else None
                        rid = rid_match.group(1) if rid_match else None

                        # Check if it's Shell.Explorer.1
                        is_shell_explorer = False
                        if prog_id and 'shell.explorer' in prog_id.lower():
                            is_shell_explorer = True
                        if clsid and clsid.strip('{}').upper() == SHELL_EXPLORER_CLSID_STR.strip('{}').upper():
                            is_shell_explorer = True

                        if is_shell_explorer:
                            print(f"    [+] Found OLEObject in {doc_xml_path}:")
                            if prog_id:
                                print(f"        ProgID: {prog_id}")
                            if clsid:
                                print(f"        CLSID: {clsid}")

                            # Resolve relationship to find binary
                            if rid:
                                rels_path = f"{folder}/_rels/{os.path.basename(doc_xml_path)}.rels"
                                if rels_path in z.namelist():
                                    rels_data = z.read(rels_path).decode('utf-8', errors='ignore')
                                    target_match = re.search(
                                        rf'<Relationship[^>]+Id=["\']' + re.escape(rid) + r'["\'][^>]+Target=["\']([^"\']+)["\']',
                                        rels_data, re.IGNORECASE
                                    )
                                    if target_match:
                                        target = target_match.group(1)
                                        # Resolve relative path
                                        if not target.startswith('/'):
                                            target_path = f"{folder}/{target}"
                                        else:
                                            target_path = target.lstrip('/')

                                        # Normalize path
                                        target_path = target_path.replace('\\', '/')

                                        print(f"        Target: {target_path}")

                                        # Try to find and process the binary
                                        if target_path in z.namelist():
                                            self.process_ooxml_embedding(z, target_path, prog_id or clsid)
                                        else:
                                            # Try fuzzy match
                                            matches = [n for n in z.namelist() if n.endswith(os.path.basename(target))]
                                            if matches:
                                                self.process_ooxml_embedding(z, matches[0], prog_id or clsid)
                                            else:
                                                print(f"        [!] Binary not found: {target_path}")
                except Exception as e:
                    pass

            # Fallback: Check all embeddings folders for orphaned objects
            embeddings = [f for f in z.namelist()
                         if 'embedding' in f.lower() and not f.endswith('/')]

            for emb_path in embeddings:
                try:
                    emb_data = z.read(emb_path)
                    # Check for Shell.Explorer.1 signatures in the embedded data
                    if SHELL_EXPLORER_CLSID_BYTES in emb_data or REGEX_SHELL_EXPLORER.search(emb_data):
                        print(f"    [+] Found Shell.Explorer.1 signature in orphaned embedding: {emb_path}")
                        self.process_ooxml_embedding(z, emb_path, "Unknown (orphaned)")
                except: pass

    def process_ooxml_embedding(self, zipfile_obj, emb_path, identifier):
        """Process an OOXML embedded object"""
        try:
            emb_data = zipfile_obj.read(emb_path)
            emb_stream = io.BytesIO(emb_data)

            if olefile.isOleFile(emb_stream):
                print(f"        [+] Processing OLE compound file: {emb_path}")
                self.handle_legacy(emb_stream, source_desc=f"OOXML_{identifier}_{emb_path}", force_scan=True)
            else:
                # Raw data fallback
                self.carve_stream(emb_data, f"OOXML_{identifier}_{emb_path}")
        except Exception as e:
            print(f"        [!] Error processing {emb_path}: {e}")

    def parse_rels_for_bin(self, rels_data):
        try:
            root = ET.fromstring(rels_data)
            for rel in root.findall('{http://schemas.openxmlformats.org/package/2006/relationships}Relationship'):
                target = rel.attrib.get('Target')
                if target and target.endswith('.bin'):
                    return target
        except: pass
        return None

    # =========================================================================
    # LEGACY OLE HANDLER
    # =========================================================================
    def handle_legacy(self, file_input, source_desc=None, force_scan=False):
        try:
            ole = olefile.OleFileIO(file_input)
        except: return

        found_any = False
        display_name = source_desc if source_desc else "Storage"

        for entry in ole.listdir():
            if entry[-1] == '\x01CompObj':
                comp_obj_path = entry
                storage_path = entry[:-1]
                
                try:
                    with ole.openstream(comp_obj_path) as f:
                        data = f.read()
                        # Check CLSID or Regex String
                        match_clsid = SHELL_EXPLORER_CLSID_BYTES in data
                        match_regex = REGEX_SHELL_EXPLORER.search(data)
                        
                        if match_clsid or match_regex:
                            path_str = '/'.join(storage_path)
                            print(f"    [+] Found Shell.Explorer.1 in {display_name}: {path_str}")
                            found_any = True
                            self.scan_storage_for_lnk(ole, storage_path)
                except: continue
        # If we have a metadata match but no CompObj hit, scan all streams
        if force_scan and not found_any:
            self.scan_storage_for_lnk(ole, ())
            # Also brute-scan the full OLE blob for LNK signatures
            self.scan_ole_raw_for_lnk(ole, display_name)

    def scan_storage_for_lnk(self, ole, storage_path):
        prefix = list(storage_path) if not isinstance(storage_path, list) else storage_path
        for child in ole.listdir():
            if child[:len(prefix)] == prefix and child != prefix:
                stream_name = child[-1]
                full_name = "/".join(child)
                if stream_name not in ['\x01CompObj', '\x05SummaryInformation', '\x05DocumentSummaryInformation']:
                    with ole.openstream(child) as f:
                        data = f.read()
                        self.carve_stream(data, full_name)
                        self.heuristic_scan_stream(data, full_name)
                        if full_name.endswith("CONTENTS"):
                            self.parse_shell_explorer_contents(data, full_name)
        # Dump all streams for manual inspection when force-scan is used
        self.dump_all_streams(ole, storage_path)
        # Summarize streams to spot suspicious blobs
        self.summarize_streams(ole, storage_path)

    def dump_all_streams(self, ole, storage_path):
        # Only dump full OLE once (root scan)
        if storage_path != (): 
            return
        if not os.path.exists("dumps"): os.makedirs("dumps")
        for child in ole.listdir():
            if child[-1] in ['\x01CompObj', '\x05SummaryInformation', '\x05DocumentSummaryInformation']:
                continue
            try:
                with ole.openstream(child) as f:
                    data = f.read()
                clean_name = "_".join(child).replace("\\", "_").replace("/", "_")
                fname = os.path.join("dumps", f"stream_{clean_name}.bin")
                with open(fname, "wb") as out:
                    out.write(data)
            except: 
                continue

    def scan_ole_raw_for_lnk(self, ole, display_name):
        # Read full OLE file bytes and scan for LNK headers anywhere
        try:
            data = ole.fp.read()
        except:
            return
        idx = 0
        found = False
        while True:
            idx = data.find(LNK_HEADER_SIG, idx)
            if idx == -1:
                break
            found = True
            print(f"    [>] Raw OLE scan hit at offset {idx} in {display_name}")
            self.carve_stream(data, f"{display_name}_OLE_RAW_{idx}")
            idx += 4
        if not found:
            print(f"    [.] Raw OLE scan: no LNK header signatures found in {display_name}")

    def summarize_streams(self, ole, storage_path):
        if storage_path != (): 
            return
        print("    [i] Stream summary:")
        for child in ole.listdir():
            if child[-1] in ['\x01CompObj', '\x05SummaryInformation', '\x05DocumentSummaryInformation']:
                continue
            try:
                with ole.openstream(child) as f:
                    data = f.read()
                name = "/".join(child)
                size = len(data)
                ent = self.entropy(data)
                ascii_cnt = self.count_ascii_strings(data)
                u16_cnt = self.count_utf16le_strings(data)
                flag = []
                if b"Shell.Explorer.1" in data:
                    flag.append("ascii:Shell.Explorer.1")
                if b"S\x00h\x00e\x00l\x00l\x00.\x00E\x00x\x00p\x00l\x00o\x00r\x00e\x00r\x00.\x001\x00" in data:
                    flag.append("utf16:Shell.Explorer.1")
                flag_str = ",".join(flag) if flag else "-"
                print(f"        - {name} | {size} bytes | H={ent:.2f} | ascii={ascii_cnt} | u16={u16_cnt} | {flag_str}")
            except:
                continue

    def entropy(self, data):
        if not data:
            return 0.0
        counts = [0]*256
        for b in data:
            counts[b] += 1
        import math
        ent = 0.0
        inv_len = 1.0/len(data)
        for c in counts:
            if c:
                p = c * inv_len
                ent -= p * math.log2(p)
        return ent

    def count_ascii_strings(self, data, min_len=4):
        count = 0
        run = 0
        for b in data:
            if 32 <= b <= 126:
                run += 1
            else:
                if run >= min_len:
                    count += 1
                run = 0
        if run >= min_len:
            count += 1
        return count

    def count_utf16le_strings(self, data, min_len=4):
        count = 0
        run = 0
        i = 0
        n = len(data)
        while i + 1 < n:
            b0 = data[i]
            b1 = data[i+1]
            if 32 <= b0 <= 126 and b1 == 0:
                run += 1
            else:
                if run >= min_len:
                    count += 1
                run = 0
            i += 2
        if run >= min_len:
            count += 1
        return count

    def heuristic_scan_stream(self, data, stream_name):
        # Look for LNK CLSID signature even if the header size is missing/corrupted
        hits = []
        idx = 0
        while True:
            idx = data.find(LNK_CLSID_BYTES, idx)
            if idx == -1:
                break
            hits.append(idx)
            idx += 4
        if not hits:
            return
        print(f"    [>] Heuristic: {len(hits)} LNK CLSID hit(s) in {stream_name}")
        if not os.path.exists("dumps"): os.makedirs("dumps")
        for off in hits:
            # Try to align to potential header start (4 bytes before CLSID)
            start = max(0, off - 4)
            end = min(len(data), off + 4096)
            snippet = data[start:end]
            clean_name = stream_name.replace("/", "_").replace("\\", "_")
            fname = os.path.join("dumps", f"heuristic_{clean_name}_{off}.bin")
            with open(fname, "wb") as out:
                out.write(snippet)
            # Attempt a carve from the guessed header start
            if start + 4 <= len(data):
                self.carve_stream(data[start:], f"{stream_name}#heuristic_{off}")

    def parse_shell_explorer_contents(self, data, stream_name):
        # Per public research, persisted Shell.Explorer.1 objects often contain a ShellLink at offset 0x4C
        if len(data) < 0x4C + 4:
            return
        sub = data[0x4C:]
        if not sub.startswith(LNK_HEADER_SIG):
            return
        print(f"    [>] Shell.Explorer.1 CONTENTS LNK at 0x4C in {stream_name}")
        idlist = self.parse_shelllink_idlist(sub)
        if idlist:
            idlist_size, items = idlist
            print(f"        --> IDLIST size: {idlist_size} bytes, items: {len(items)}")
            self.dump_idlist(items, stream_name)
            # Decode item hints (GUID + URL strings)
            decoded = self.decode_idlist_items(items)
            for line in decoded:
                print(f"        --> {line}")
            # Collect JSON output
            json_items, guid_list = self.json_idlist_items(items)
            self.json_results.append({
                "source_file": self.current_file,
                "stream": stream_name,
                "idlist_size": idlist_size,
                "guids": guid_list,
                "items": json_items
            })
        else:
            print("        [!] No IDLIST parsed from ShellLink")
        # Also show any raw UTF-16 strings present in the LNK blob
        u16 = self.extract_utf16le_strings(sub)
        if u16:
            print(f"        --> UTF-16LE strings (LNK blob): {u16[:3]}")

    def extract_utf16le_strings(self, data, min_len=4, max_count=10):
        import re
        hits = re.findall(rb'(?:[ -~]\x00){%d,}' % min_len, data)
        out = []
        for h in hits[:max_count]:
            out.append(h.decode('utf-16le', errors='ignore'))
        return out

    def parse_shelllink_idlist(self, data):
        # Minimal ShellLink parser to extract IDLIST (MS-SHLLINK)
        if len(data) < 0x4C + 2:
            return None
        header_size = struct.unpack('<I', data[0:4])[0]
        if header_size != 0x4C:
            return None
        link_flags = struct.unpack('<I', data[0x14:0x18])[0]
        has_idlist = (link_flags & 0x00000001) != 0
        idlist_offset = 0x4C
        if not has_idlist:
            # Some persisted objects may still place an IDLIST here; attempt parse anyway
            pass
        if idlist_offset + 2 > len(data):
            return None
        idlist_size = struct.unpack('<H', data[idlist_offset:idlist_offset+2])[0]
        if idlist_size == 0 or idlist_offset + 2 + idlist_size > len(data):
            return None
        idlist_data = data[idlist_offset+2:idlist_offset+2+idlist_size]
        items = []
        ptr = 0
        while ptr + 2 <= len(idlist_data):
            sz = struct.unpack('<H', idlist_data[ptr:ptr+2])[0]
            if sz == 0:
                break
            if ptr + sz > len(idlist_data):
                break
            items.append(idlist_data[ptr:ptr+sz])
            ptr += sz
        return (idlist_size, items)

    def extract_strings_from_items(self, items, min_len=4):
        out = []
        for item in items:
            out.extend(self.extract_utf16le_strings(item, min_len=min_len, max_count=3))
            out.extend(self.extract_ascii_strings(item, min_len=min_len, max_count=3))
        # de-dupe while preserving order
        seen = set()
        deduped = []
        for s in out:
            if s not in seen:
                seen.add(s)
                deduped.append(s)
        return deduped

    def extract_ascii_strings(self, data, min_len=4, max_count=10):
        import re
        hits = re.findall(rb'[ -~]{%d,}' % min_len, data)
        out = []
        for h in hits[:max_count]:
            out.append(h.decode('ascii', errors='ignore'))
        return out

    def decode_idlist_items(self, items):
        # Minimal, cross-platform decoding for common Shell Item patterns.
        decoded = []
        for idx, item in enumerate(items):
            if len(item) < 3:
                continue
            size = struct.unpack('<H', item[:2])[0]
            data = item[2:]
            item_type = data[0] if data else None
            decoded_item = self.parse_shell_item(data, idx, size)
            if decoded_item:
                decoded.append(decoded_item)
                continue
            # URL-like items often embed UTF-16 strings
            u16 = self.extract_utf16le_strings(data, min_len=8, max_count=2)
            if u16:
                classified = self.classify_strings(u16)
                decoded.append(f"Item {idx}: {classified}")
                continue
            asc = self.extract_ascii_strings(data, min_len=8, max_count=2)
            if asc:
                decoded.append(f"Item {idx}: ASCII {asc}")
                continue
            decoded.append(f"Item {idx}: type=0x{item_type:02x} size={size}")
        return decoded

    def guid_from_bytes_le(self, b):
        if len(b) != 16:
            return ""
        # GUID fields are little-endian for the first 3 components
        d1 = struct.unpack('<I', b[0:4])[0]
        d2 = struct.unpack('<H', b[4:6])[0]
        d3 = struct.unpack('<H', b[6:8])[0]
        d4 = b[8:10]
        d5 = b[10:16]
        return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4.hex()}-{d5.hex()}"

    def guid_label(self, guid):
        # Common shell GUIDs (partial list); values are lowercase
        return self.known_folder_guids().get(guid.lower(), "")

    def known_folder_guids(self):
        if hasattr(self, "_known_folder_cache"):
            return self._known_folder_cache
        labels = {}
        # Optional external map
        paths = []
        if self.knownfolders_path:
            paths.append(self.knownfolders_path)
        paths += ["knownfolders.json", os.path.join(os.path.dirname(__file__), "knownfolders.json")]
        for path in paths:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        extra = json.load(f)
                    for k, v in extra.items():
                        labels[k.lower()] = v
                except Exception:
                    pass
        # Fallback minimal map if no file is present
        if not labels:
            labels = {
                "00021401-0000-0000-c000-000000000046": "ShellLink CLSID",
                "871c5380-42a0-1069-a2ea-08002b30309d": "Internet Folder (Internet Explorer)",
                "0ac0837c-bbf8-452a-850d-79d08e667ca7": "Computer",
                "1b3ea5dc-b587-4786-b4ef-bd1dc332aeae": "Libraries",
                "20d04fe0-3aea-1069-a2d8-08002b30309d": "This PC (My Computer)",
                "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
                "374de290-123f-4565-9164-39c4925e467b": "Downloads",
                "4bd8d571-6d19-48d3-be97-422220080e43": "Music",
                "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
                "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
                "b97d20bb-f46a-4c97-ba10-5e3608430854": "Startup",
                "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
                "f1b32785-6fba-4fcf-9d55-7b8e7f157091": "Local AppData",
                "fdd39ad0-238f-46af-adb4-6c85480369c7": "Documents",
                "18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Videos",
            }
        self._known_folder_cache = labels
        return labels

    def parse_shell_item(self, data, idx, size):
        if not data:
            return None
        class_type = data[0]
        masked = class_type & 0x70
        # Root folder item
        if class_type == 0x1F and len(data) >= 18:
            guid = self.guid_from_bytes_le(data[2:18])
            label = self.guid_label(guid)
            if label:
                return f"Item {idx}: Root GUID {guid} ({label})"
            return f"Item {idx}: Root GUID {guid}"
        # Volume item
        if masked == 0x20 and len(data) >= 2:
            flags = data[1]
            hints = self.extract_ascii_strings(data, min_len=2, max_count=2)
            return f"Item {idx}: Volume item flags=0x{flags:02x} hints={hints}"
        # File entry item
        if masked == 0x30 and len(data) >= 12:
            file_size = struct.unpack('<I', data[2:6])[0]
            mod_time = struct.unpack('<I', data[6:10])[0]
            file_attrs = struct.unpack('<H', data[10:12])[0]
            name = self.read_cstring(data[12:])
            ext = self.parse_file_entry_extension(data)
            long_name = ext.get("long_name", "")
            dt = self.dos_date_time(mod_time)
            name_part = long_name if long_name else name
            ext_blocks = self.parse_extension_blocks(data)
            if ext_blocks:
                ext_summary = f" ext_blocks={len(ext_blocks)}"
            else:
                ext_summary = ""
            return (
                f"Item {idx}: File entry name={name_part!r} size={file_size} "
                f"attrs=0x{file_attrs:04x} mod={dt}{ext_summary}"
            )
        # Network location item
        if masked == 0x40:
            u16 = self.extract_utf16le_strings(data, min_len=4, max_count=2)
            asc = self.extract_ascii_strings(data, min_len=4, max_count=2)
            return f"Item {idx}: Network item u16={u16} ascii={asc}"
        # URI item (0x61)
        if class_type == 0x61:
            u16 = self.extract_utf16le_strings(data, min_len=4, max_count=2)
            if u16:
                return f"Item {idx}: URL item {u16}"
        return None

    def read_cstring(self, data):
        end = data.find(b"\x00")
        if end == -1:
            end = len(data)
        try:
            return data[:end].decode("ascii", errors="ignore")
        except Exception:
            return ""

    def extract_long_name_from_extension(self, data):
        # Backwards-compat shim (unused)
        ext = self.parse_file_entry_extension(data)
        return ext.get("long_name", "")

    def parse_file_entry_extension(self, data):
        # Parse common file entry extension block (BEEF0004)
        out = {}
        blocks = self.parse_extension_blocks(data)
        for blk in blocks:
            if blk.get("signature") == "0xbeef0004":
                u16 = blk.get("utf16_strings") or []
                if u16:
                    out["long_name"] = u16[0]
        return out

    def parse_extension_blocks(self, data):
        # Generic extension block parser: size (2), version (2), signature (4)
        blocks = []
        sig = b"\x04\x00\xef\xbe"  # 0xBEEF0004 (little endian)
        idx = 0
        while True:
            off = data.find(sig, idx)
            if off == -1:
                break
            if off < 4:
                idx = off + 4
                continue
            start = off - 4
            if start + 8 > len(data):
                idx = off + 4
                continue
            size = struct.unpack('<H', data[start:start+2])[0]
            version = struct.unpack('<H', data[start+2:start+4])[0]
            if size < 8 or start + size > len(data):
                idx = off + 4
                continue
            blk = data[start:start+size]
            utf16 = self.extract_utf16le_strings(blk, min_len=4, max_count=6)
            ascii_s = self.extract_ascii_strings(blk, min_len=4, max_count=6)
            fat_times = self.scan_fat_timestamps(blk)
            sig_val = struct.unpack('<I', data[off:off+4])[0]
            detail = self.parse_extension_block_detail(blk, sig_val)
            blocks.append({
                "offset": start,
                "size": size,
                "version": version,
                "signature": "0x%08x" % sig_val,
                "signature_name": self.extension_signature_name(sig_val),
                "utf16_strings": utf16,
                "ascii_strings": ascii_s,
                "fat_timestamps": fat_times,
                "detail": detail
            })
            idx = start + size
        return blocks

    def extension_signature_name(self, sig_val):
        names = {
            0xBEEF0004: "File entry extension",
            0xBEEF0003: "GUID extension",
            0xBEEF0000: "GUID extension",
            0xBEEF0019: "GUID extension",
            0xBEEF0008: "Recycle bin extension",
            0xBEEF0025: "Timestamp extension",
        }
        return names.get(sig_val, "")

    def parse_extension_block_detail(self, blk, sig_val):
        # Best-effort parsing; layout varies by signature and OS.
        detail = {"heuristic": True}
        if len(blk) < 8:
            return detail
        # Common header is size(2), version(2), signature(4)
        payload = blk[8:]

        if sig_val == 0xBEEF0004:
            # File entry extension block: contains timestamps, long/short names, and MFT reference.
            # Fixed-offset timestamps (best-effort): created, accessed, written
            if len(payload) >= 12:
                c = struct.unpack('<I', payload[0:4])[0]
                a = struct.unpack('<I', payload[4:8])[0]
                w = struct.unpack('<I', payload[8:12])[0]
                c_dt = self.dos_date_time(c)
                a_dt = self.dos_date_time(a)
                w_dt = self.dos_date_time(w)
                if c_dt != "N/A":
                    detail["created_time"] = c_dt
                if a_dt != "N/A":
                    detail["access_time"] = a_dt
                if w_dt != "N/A":
                    detail["write_time"] = w_dt

            # Extract names
            u16 = self.extract_utf16le_strings(payload, min_len=4, max_count=4)
            asc = self.extract_ascii_strings(payload, min_len=4, max_count=4)
            detail["long_name"] = u16[0] if u16 else None
            detail["short_name"] = asc[0] if asc else None

            # Heuristic: last 8 bytes may be an NTFS file reference (6-byte entry + 2-byte sequence)
            if len(payload) >= 8:
                ref = payload[-8:]
                entry = int.from_bytes(ref[0:6], "little")
                seq = int.from_bytes(ref[6:8], "little")
                if entry > 0 or seq > 0:
                    detail["mft_entry"] = entry
                    detail["mft_sequence"] = seq

        elif sig_val in (0xBEEF0003, 0xBEEF0000, 0xBEEF0019):
            # GUID extension blocks: try GUID at payload[0:16]
            if len(payload) >= 16:
                guid = self.guid_from_bytes_le(payload[0:16])
                detail["guid"] = guid
                detail["guid_label"] = self.guid_label(guid) or None

        elif sig_val == 0xBEEF0008:
            # Recycle bin extension: try to capture original path/name strings
            u16 = self.extract_utf16le_strings(payload, min_len=4, max_count=4)
            asc = self.extract_ascii_strings(payload, min_len=4, max_count=4)
            if u16:
                detail["strings"] = u16
            elif asc:
                detail["strings"] = asc

        elif sig_val == 0xBEEF0025:
            # Timestamp extension: collect FAT timestamps
            fat_times = self.scan_fat_timestamps(payload)
            if fat_times:
                detail["timestamps"] = [t["datetime"] for t in fat_times]

        return detail

    def scan_fat_timestamps(self, data):
        # Heuristic scan for FAT date/time dwords within a block
        out = []
        for off in range(0, max(0, len(data) - 4), 2):
            val = struct.unpack('<I', data[off:off+4])[0]
            date = (val >> 16) & 0xFFFF
            time = val & 0xFFFF
            day = date & 0x1F
            month = (date >> 5) & 0x0F
            year = ((date >> 9) & 0x7F) + 1980
            sec = (time & 0x1F) * 2
            minute = (time >> 5) & 0x3F
            hour = (time >> 11) & 0x1F
            if 1980 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31 and hour <= 23 and minute <= 59 and sec <= 59:
                out.append({
                    "offset": off,
                    "value": "0x%08x" % val,
                    "datetime": f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"
                })
                if len(out) >= 6:
                    break
        return out

    def json_idlist_items(self, items):
        json_items = []
        guids = []
        for idx, item in enumerate(items):
            if len(item) < 3:
                continue
            size = struct.unpack('<H', item[:2])[0]
            data = item[2:]
            class_type = data[0] if data else None
            entry = {"index": idx, "size": size, "class_type": f"0x{class_type:02x}" if class_type is not None else None}
            if class_type == 0x1F and len(data) >= 18:
                guid = self.guid_from_bytes_le(data[2:18])
                entry["guid"] = guid
                entry["guid_label"] = self.guid_label(guid) or None
                guids.append(guid)
            u16 = self.extract_utf16le_strings(data, min_len=4, max_count=4)
            if u16:
                entry["utf16_strings"] = u16
                entry["classified"] = self.classify_strings(u16)
            asc = self.extract_ascii_strings(data, min_len=4, max_count=4)
            if asc:
                entry["ascii_strings"] = asc
            entry["extension_blocks"] = self.parse_extension_blocks(data)
            json_items.append(entry)
        return json_items, guids

    def dos_date_time(self, dt):
        # MS-DOS date/time: high 16 bits date, low 16 bits time
        date = (dt >> 16) & 0xFFFF
        time = dt & 0xFFFF
        day = date & 0x1F
        month = (date >> 5) & 0x0F
        year = ((date >> 9) & 0x7F) + 1980
        sec = (time & 0x1F) * 2
        minute = (time >> 5) & 0x3F
        hour = (time >> 11) & 0x1F
        if month == 0 or day == 0:
            return "N/A"
        try:
            return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"
        except Exception:
            return "N/A"

    def classify_strings(self, strs):
        # Prefer URL/UNC/path labeling when obvious
        for s in strs:
            low = s.lower()
            if low.startswith("http://") or low.startswith("https://"):
                return f"URL {strs}"
            if low.startswith("\\\\"):
                return f"UNC {strs}"
            if len(s) >= 2 and s[1] == ":":
                return f"Path {strs}"
        return f"UTF-16 {strs}"

    def dump_idlist(self, items, stream_name):
        if not os.path.exists("dumps"):
            os.makedirs("dumps")
        clean = stream_name.replace("/", "_").replace("\\", "_")
        for idx, item in enumerate(items):
            fname = os.path.join("dumps", f"idlist_{clean}_{idx}.bin")
            with open(fname, "wb") as f:
                f.write(item)

    # =========================================================================
    # CARVER & PARSER
    # =========================================================================
    def carve_stream(self, data, stream_name):
        start_idx = data.find(LNK_HEADER_SIG)
        if start_idx == -1: return

        print(f"    [>] Carving LNK from stream: {stream_name}")
        end_idx = self.structural_walk(data, start_idx)
        if not end_idx:
            term = data.find(b'\x00\x00\x00\x00', start_idx + 76)
            if term != -1: end_idx = term + 4
        
        if not end_idx:
            print("        [-] Failed to find end of LNK structure.")
            return

        lnk_bytes = data[start_idx:end_idx]
        overlay = data[end_idx:]

        # LNK parsing intentionally omitted; this tool focuses on Shell.Explorer.1 IDLISTs.

        if len(overlay) > 16:
            print(f"        [!] ALERT: {len(overlay)} bytes of suspicious overlay data found!")
            self.dump_overlay(overlay, stream_name)

    def structural_walk(self, data, start_idx):
        try:
            ptr = start_idx + 76
            id_sz = struct.unpack('<H', data[ptr:ptr+2])[0]
            ptr += 2 + id_sz
            info_sz = struct.unpack('<I', data[ptr:ptr+4])[0]
            ptr += info_sz
            flags = struct.unpack('<I', data[start_idx+20:start_idx+24])[0]
            for bit in range(5):
                if flags & (1 << bit):
                    str_len = struct.unpack('<H', data[ptr:ptr+2])[0]
                    ptr += 2 + (str_len * 2)
            while ptr < len(data):
                blk_sz = struct.unpack('<I', data[ptr:ptr+4])[0]
                if blk_sz < 4: return ptr + 4
                ptr += blk_sz
        except: return None

    def dump_overlay(self, data, source_name):
        clean_name = source_name.replace("/", "_").replace("\\", "_")
        if not os.path.exists("dumps"): os.makedirs("dumps")
        fname = os.path.join("dumps", f"overlay_{clean_name}.bin")
        with open(fname, "wb") as f: f.write(data)
        print(f"        [+] Dumped to: {fname}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Shell.Explorer.1 OLE parser with IDLIST decoding")
    parser.add_argument("--knownfolders", dest="knownfolders", help="Path to knownfolders.json")
    parser.add_argument("target", help="File, glob, or directory to scan")
    parser.add_argument("--json-out", dest="json_out", help="Path to write JSON output")
    args = parser.parse_args()
    app = ShellExplorerHunter(knownfolders_path=args.knownfolders, json_out=args.json_out)
    app.scan_path(args.target)
