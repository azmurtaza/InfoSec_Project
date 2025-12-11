
import pefile
import os
import math
import mmap
import numpy as np
from collections import Counter

def calculate_entropy(data):
    if not data:
        return 0.0
    occurences = Counter(data)
    d_len = len(data)
    entropy = -sum((count / d_len) * math.log2(count / d_len) for count in occurences.values())
    return entropy

def extract_pe_features(file_path):
    features = {}
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"Error parsing PE {file_path}: {e}")
        return None

    try:
        # --- DOS HEADER ---
        features['e_cblp'] = pe.DOS_HEADER.e_cblp
        features['e_cp'] = pe.DOS_HEADER.e_cp
        features['e_cparhdr'] = pe.DOS_HEADER.e_cparhdr
        features['e_maxalloc'] = pe.DOS_HEADER.e_maxalloc
        features['e_sp'] = pe.DOS_HEADER.e_sp
        features['e_lfanew'] = pe.DOS_HEADER.e_lfanew
        
        # --- FILE HEADER ---
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        features['CreationYear'] = pe.FILE_HEADER.TimeDateStamp 
        
        # FH_char0 to FH_char14
        chars = pe.FILE_HEADER.Characteristics
        for i in range(15):
            features[f'FH_char{i}'] = (chars >> i) & 1

        # --- OPTIONAL HEADER ---
        opt = pe.OPTIONAL_HEADER
        features['MajorLinkerVersion'] = opt.MajorLinkerVersion
        features['MinorLinkerVersion'] = opt.MinorLinkerVersion
        features['SizeOfCode'] = opt.SizeOfCode
        features['SizeOfInitializedData'] = opt.SizeOfInitializedData
        features['SizeOfUninitializedData'] = opt.SizeOfUninitializedData
        features['AddressOfEntryPoint'] = opt.AddressOfEntryPoint
        features['BaseOfCode'] = opt.BaseOfCode
        
        # BaseOfData handling (only in 32-bit PEs)
        features['BaseOfData'] = getattr(opt, 'BaseOfData', 0)
            
        features['ImageBase'] = opt.ImageBase
        features['SectionAlignment'] = opt.SectionAlignment
        features['FileAlignment'] = opt.FileAlignment
        features['MajorOperatingSystemVersion'] = opt.MajorOperatingSystemVersion
        features['MinorOperatingSystemVersion'] = opt.MinorOperatingSystemVersion
        features['MajorImageVersion'] = opt.MajorImageVersion
        features['MinorImageVersion'] = opt.MinorImageVersion
        features['MajorSubsystemVersion'] = opt.MajorSubsystemVersion
        features['MinorSubsystemVersion'] = opt.MinorSubsystemVersion
        features['SizeOfImage'] = opt.SizeOfImage
        features['SizeOfHeaders'] = opt.SizeOfHeaders
        features['CheckSum'] = opt.CheckSum
        features['Subsystem'] = opt.Subsystem
        
        # DLL Characteristics (0-10)
        dll_chars = opt.DllCharacteristics
        for i in range(11):
            features[f'OH_DLLchar{i}'] = (dll_chars >> i) & 1

        features['SizeOfStackReserve'] = opt.SizeOfStackReserve
        features['SizeOfStackCommit'] = opt.SizeOfStackCommit
        features['SizeOfHeapReserve'] = opt.SizeOfHeapReserve
        features['SizeOfHeapCommit'] = opt.SizeOfHeapCommit
        features['LoaderFlags'] = opt.LoaderFlags

        # --- DERIVED FEATURES ---
        
        # Sections Analysis
        sus_sections = 0
        non_sus_sections = 0
        e_text_entropy = 0.0
        e_data_entropy = 0.0
        
        # Standard section characteristics usually:
        # IMAGE_SCN_MEM_WRITE = 0x80000000
        # IMAGE_SCN_MEM_EXECUTE = 0x20000000
        
        for section in pe.sections:
            props = section.Characteristics
            is_write = (props & 0x80000000)
            is_exec = (props & 0x20000000)
            
            # Identify suspicious sections (Write + Execute)
            if is_write and is_exec:
                sus_sections += 1
            else:
                non_sus_sections += 1
            
            # Entropy for .text and .data
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if name.startswith('.text'):
                e_text_entropy = calculate_entropy(section.get_data())
            elif name.startswith('.data'):
                e_data_entropy = calculate_entropy(section.get_data())

        features['sus_sections'] = sus_sections
        features['non_sus_sections'] = non_sus_sections
        
        # Entropy
        features['E_text'] = e_text_entropy
        features['E_data'] = e_data_entropy
        
        # File level features
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                features['filesize'] = len(data)
                features['E_file'] = calculate_entropy(data)
        except:
            features['filesize'] = 0
            features['E_file'] = 0

        # Packer - Placeholder (Simple heuristic or 0)
        # For strict sync with ClaMP dataset which implies existing label, 
        # we default to 0 (False) to avoid mismatch, as accurate packer detection needs signature DB.
        features['packer'] = 0 
            
        return features

    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

if __name__ == "__main__":
    # Test on itself or a dummy
    import json
    f = extract_pe_features("src/check_data.py") # Will fail PE parse obviously, but tests logic
    print("Test run complete (expected error on non-PE)")