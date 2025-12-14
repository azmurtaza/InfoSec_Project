
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

def extract_features(file_path):
    """
    Extracts features from a file. 
    Tries to parse as PE to get PE features.
    If that fails (or for all files), extracts raw byte features.
    """
    features = {}

    # --- Raw File Features (Always extracted) ---
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
            
        features['filesize'] = len(raw_data)
        features['E_file'] = calculate_entropy(raw_data)
        
        # Byte Histogram (Byte_0 ... Byte_255)
        # Normalize counts by filesize for consistency
        byte_counts = Counter(raw_data)
        for i in range(256):
            features[f'Byte_{i}'] = byte_counts.get(i, 0) / (len(raw_data) + 1e-9)

        # Simple Suspicious String Analysis (Raw Scan)
        suspicious_keywords = [b"cmd.exe", b"powershell", b"urlmon", b"http", b"download", b"temp", b"socket"]
        features['Suspicious_Strings'] = 0
        raw_data_lower = raw_data.lower()
        for keyword in suspicious_keywords:
            if keyword in raw_data_lower:
                features['Suspicious_Strings'] += 1

    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

    # --- PE Features (Optional) ---
    pe = None
    try:
        pe = pefile.PE(file_path)
    except:
        pass # Not a PE file or corrupted

    if pe:
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

            # --- DERIVED PE FEATURES ---
            
            # Sections Analysis
            sus_sections = 0
            non_sus_sections = 0
            e_text_entropy = 0.0
            e_data_entropy = 0.0
            
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
            features['E_text'] = e_text_entropy
            features['E_data'] = e_data_entropy
            
            features['packer'] = 0 
                
            # IAT Count
            try:
                pe.parse_data_directories()
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    features['IAT_Count'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                else:
                    features['IAT_Count'] = 0
            except:
                features['IAT_Count'] = 0

            # Resource Entropy
            features['Resource_Entropy'] = 0
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                        if hasattr(resource_type, 'directory'):
                            for resource_id in resource_type.directory.entries:
                                if hasattr(resource_id, 'directory'):
                                    for resource_lang in resource_id.directory.entries:
                                        data_rva = resource_lang.data.struct.OffsetToData
                                        size = resource_lang.data.struct.Size
                                        data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                                        features['Resource_Entropy'] = max(features['Resource_Entropy'], calculate_entropy(data))
            except Exception as e:
                pass 

            # Has Digital Signature? (Heuristic)
            # IMAGE_DIRECTORY_ENTRY_SECURITY is index 4
            try:
                security_dir_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
                if security_dir_size > 0:
                    features['has_signature'] = 1
                else:
                    features['has_signature'] = 0
            except:
                features['has_signature'] = 0 

        except Exception as e:
            print(f"Error parsing PE structure details: {e}")
            # If partial parsing, we keep what we have.
            pass
            
    else:
        # Fill missing PE features with typical 'null' values to maintain consistency if needed
        # However, ML classifiers might handle missing columns or we can let '0' be the default implies 'not present'.
        # For simplicity in this script, we just return what we have. 
        # The training pipeline handles missing columns by filling with 0.
        pass

    return features

# Legacy alias
extract_pe_features = extract_features

if __name__ == "__main__":
    # Test on itself 
    # Test on calc.exe
    target = r"C:\Windows\System32\calc.exe"
    if not os.path.exists(target):
         target = "src/feature_extraction.py"
         
    f = extract_features(target)
    if f:
        print(f"Extraction successful for {target}!")
        print(f"File Size: {f.get('filesize')}")
        print(f"Is PE? {'NumberOfSections' in f}")
        print(f"Has Signature? {f.get('has_signature')}")
    else:
        print("Extraction failed.")