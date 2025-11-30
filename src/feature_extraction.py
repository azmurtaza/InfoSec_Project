import pefile
import os
import numpy as np

def extract_pe_features(file_path):
    try:
        pe = pefile.PE(file_path)
        data = {}

        # --- 1. DOS HEADER ---
        data['e_magic'] = pe.DOS_HEADER.e_magic
        data['e_cblp'] = pe.DOS_HEADER.e_cblp
        data['e_cp'] = pe.DOS_HEADER.e_cp
        data['e_crlc'] = pe.DOS_HEADER.e_crlc
        data['e_cparhdr'] = pe.DOS_HEADER.e_cparhdr
        data['e_minalloc'] = pe.DOS_HEADER.e_minalloc
        data['e_maxalloc'] = pe.DOS_HEADER.e_maxalloc
        data['e_ss'] = pe.DOS_HEADER.e_ss
        data['e_sp'] = pe.DOS_HEADER.e_sp
        data['e_csum'] = pe.DOS_HEADER.e_csum
        data['e_ip'] = pe.DOS_HEADER.e_ip
        data['e_cs'] = pe.DOS_HEADER.e_cs
        data['e_lfarlc'] = pe.DOS_HEADER.e_lfarlc
        data['e_ovno'] = pe.DOS_HEADER.e_ovno
        data['e_res'] = pe.DOS_HEADER.e_res[0] if len(pe.DOS_HEADER.e_res) > 0 else 0
        data['e_oemid'] = pe.DOS_HEADER.e_oemid
        data['e_oeminfo'] = pe.DOS_HEADER.e_oeminfo
        data['e_res2'] = pe.DOS_HEADER.e_res2[0] if len(pe.DOS_HEADER.e_res2) > 0 else 0
        data['e_lfanew'] = pe.DOS_HEADER.e_lfanew

        # --- 2. FILE HEADER ---
        data['Machine'] = pe.FILE_HEADER.Machine
        data['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        data['CreationYear'] = pe.FILE_HEADER.TimeDateStamp # We will treat Timestamp as year proxy
        data['PointerToSymbolTable'] = pe.FILE_HEADER.PointerToSymbolTable
        data['NumberOfSymbols'] = pe.FILE_HEADER.NumberOfSymbols
        data['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        data['Characteristics'] = pe.FILE_HEADER.Characteristics

        # --- 3. OPTIONAL HEADER ---
        data['Magic'] = pe.OPTIONAL_HEADER.Magic
        data['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        data['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        data['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        data['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        data['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        data['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        data['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        
        # Handle BaseOfData (Not present in 64-bit PE32+ usually, but dataset might have it)
        try:
            data['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
        except AttributeError:
            data['BaseOfData'] = 0

        data['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        data['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        data['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        data['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        data['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        data['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        data['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
        data['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        data['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        data['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        data['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        data['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        data['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        data['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        data['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        data['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        data['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        data['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        data['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        data['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

        return data

    except Exception as e:
        print(f"Error extracting features from {file_path}: {e}")
        return None