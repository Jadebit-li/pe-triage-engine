import struct
import datetime
from collections import Counter
import math
import hashlib
import argparse

# accepting the target file path via the command line
parser = argparse.ArgumentParser(description="PE Triage Engine - static malware analysis tool")
parser.add_argument("filepath", help="Path to the PE file to analyze")
args = parser.parse_args()

path = args.filepath

# list of suspicious APIs that we will check our functions against
suspicious_apis = [
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "VirtualProtectEx",
    "NtCreateThreadEx",
    "SetWindowsHookEx",
    "QueueUserAPC"
]

# we only read the file we don't run it
with open(path, 'rb') as f:
    data = f.read()

# DOS header
# e_magc is = MZ, it is an indicator that this thing is a PE file
# e_lfanew is the file offset to the start of PE header
e_magic = struct.unpack('<H', data[0:2])[0]
e_lfanew = struct.unpack('<I', data[60:64])[0]

print(f"e_magic: {hex(e_magic)}")
print(f"e_lfanew: {hex(e_lfanew)}")

# PE signature check
pe_signature = data[e_lfanew:e_lfanew + 4]

if pe_signature == b'PE\x00\x00':
    print("Valid PE signature found")
else:
    print("NOT a valid PE file")

# File Header — one struct call for all 7 fields
file_header = struct.unpack('<HHIIIHH', data[e_lfanew+4:e_lfanew+24])

# machine info
machine = file_header[0]
# number of sections
number_of_sections = file_header[1]
# time_date_stamp: Unix timestamp of when the file was compiled/linked
time_date_stamp = file_header[2]
# deprecated COFF debug field, typically 0 in modern PE files, unused in this tool
pointer_to_symbol_table = file_header[3]
number_of_symbols = file_header[4]
# size in bytes of the Optional Header, used to calculate where the Section Table starts
size_of_optional_header = file_header[5]
characteristics = file_header[6]
# bitfield of flags describing the file (e.g. executable, DLL, 32-bit) — not used directly in this tool
build_date = datetime.datetime.fromtimestamp(time_date_stamp, datetime.UTC)

#Optional Header
#RVA of the entry point when the file is loaded into the memory
address_of_entry_point = struct.unpack('<I', data[e_lfanew+40:e_lfanew+44])[0]
#skipping past the optional header to get to the section table
#(e_lfanew+24 = start of Optional Header, since File Header is 20 bytes after the 4-byte PE signature)
section_table_start = e_lfanew + 24 + size_of_optional_header
#start of Optional Header (right after PE signature + File Header)
optional_header_start = e_lfanew + 24

#measure of randomness in the file's data
#we use entropy here to flag highly random (potentially packed/encrypted) sections
def entropy(data):
    # Counter(data) counts how many times each byte value (0-255) appears
    counts = Counter(data)
    # Total number of bytes in this chunk
    total = len(data)
    # math and formula
    total_entropy = 0.0
    
    for occurrences in counts.values():
        probability = occurrences / total
        total_entropy += probability * math.log2(probability)
    
    return -total_entropy


print(f"machine info: {hex(machine)}")
print(f"number of sections: {number_of_sections}")
print(f"date of build: {build_date}")
print(f"size of optional header: {size_of_optional_header}")
print(f"address of entry point: {hex(address_of_entry_point)}")
print(f"start of section table: {hex(section_table_start)}")

sections = []

for i in range(number_of_sections):

    # getting the file offset for all section table entry, we know they are 40 bytes each,
    entry_offset = section_table_start + (i * 40)
    # print(hex(entry_offset))
    
    # matching the official PE spec's Section Header layout (8-byte name, then a sequence of 32-bit and 16-bit fields)
    section_entry = struct.unpack('<8sIIIIIIHHI', data[entry_offset:entry_offset+40])
    virtual_address = section_entry[2]
    virtual_size = section_entry[1]
    
    # name comes back as raw bytes padded with null bytes to fill 8 characters, rstrip(b'\x00') strips those trailing nulls off, .decode('ascii') turns the bytes into an actual Python string you can print/compare.
    name = section_entry[0]
    name = name.rstrip(b'\x00').decode('ascii')

    # pointer_to_raw_data is the file offset where this section's actual bytes start on disk. size_of_raw_data is how many bytes to read from there.
    size_of_raw_data = section_entry[3]
    pointer_to_raw_data = section_entry[4]

    # getting section-wise entropy
    # lets us catch a single packed/high-entropy section even if the file overall looks normal
    section_bytes = data[pointer_to_raw_data : pointer_to_raw_data + size_of_raw_data]
    section_entropy = entropy(section_bytes)

    print(f"{name}: raw_size={hex(size_of_raw_data)}, entropy={section_entropy:.2f}")

    sections.append({"name": name, 
                     "virtual_address": virtual_address, 
                     "virtual_size": virtual_size, 
                     "pointer_to_raw_data": pointer_to_raw_data})

print(f"entropy of the entire executable: {entropy(data):.2f}")

# optional header ends with an array called Data Directory
# data directory is the last part of the Optional Header, and it's always 16 entries × 8 bytes = 128 bytes total
# start of import table's data directory entry
import_dir_offset = size_of_optional_header + optional_header_start - 128 + (1*8)

# import table rva and its size, 4 byte unsigned integers
start_of_data_dir = struct.unpack('<II', data[import_dir_offset:import_dir_offset+8])

import_table_rva = start_of_data_dir[0]
import_table_size = start_of_data_dir[1]

print(f"import directory table rva: {hex(import_table_rva)}")
print(f"size of import table: {hex(import_table_size)}")

def rva_to_offset(rva):
    # search every section to find which one this RVA falls inside
    for section in sections:
        start = section["virtual_address"]
        end = start + section["virtual_size"]  # this section's memory range once loaded

        if start <= rva < end:
            # how far past the start of this section the RVA sits
            distance_into_section = rva - start
            # section's start on disk + distance in = exact file offset
            file_offset = section["pointer_to_raw_data"] + distance_into_section
            return file_offset
    
    # RVA didn't fall inside any known section can happen with a corrupted 
    # or deliberately malformed file. Error message
    raise ValueError(f"RVA {hex(rva)} does not fall within any section")

import_table_offset = rva_to_offset(import_table_rva)
print(hex(import_table_offset))

# reading null-terminated strings
def read_string(offset):
    name_bytes = bytearray()  #An empty, growable byte buffer to collect the string's characters one at a time as you read them.
    pos = offset #current reading position in the file
    
    while True:
        current_byte = data[pos]
        
        if current_byte == 0:   #stop at null(0x00)
            break
        
        name_bytes.append(current_byte)
        pos += 1
    
    name = name_bytes.decode('ascii')   #convert into actual python string using ASCII decoding
    return name

imphash_parts = []

found_suspicious = []

# # PE thunk (import entry) size and ordinal-flag position differ between x86 and x64 
if machine == 0x8664:
    thunk_size = 8
    thunk_format = '<Q'
    ordinal_flag = 0x8000000000000000
else:
    thunk_size = 4
    thunk_format = '<I'
    ordinal_flag = 0x80000000

i = 0
while True:   #walking DLLs
    entry_offset = import_table_offset + (i * 20)   #20 bytes for each entry in thr import directory table
    import_entry = struct.unpack('<IIIII', data[entry_offset:entry_offset+20])

     # list is terminated by one final entry where every field is zero
    all_zero = True
    for n in import_entry:
        if n != 0:
            all_zero = False
    
    if all_zero:
        break

    # import_entry[3] is the RVA pointing to the DLL's name string, so we convert it to offset and read the string
    dll_name_offset = rva_to_offset(import_entry[3])
    dll_name = read_string(dll_name_offset)
    # used while computing hash
    dll_name_for_hash = dll_name.split('.')[0]
    print(f" DLL name: {dll_name}")

    # RVA of the DLL's import lookup table(ilt) - actual list of functions imported from the specific DLL
    ilt_offset = rva_to_offset(import_entry[0])
    
    j = 0
    while True:
        thunk_offset = ilt_offset + (j * thunk_size)
        thunk = struct.unpack(thunk_format, data[thunk_offset:thunk_offset+thunk_size])[0]
    
        if thunk == 0:
            break

        # function is imported by number not name
        if thunk & ordinal_flag:
            ordinal_number = thunk & 0xFFFF
            print(f"   (ordinal import: {ordinal_number}, name unavailable)")
            imphash_parts.append(f"{dll_name_for_hash}.ord{ordinal_number}".lower())

        # else thunk itself is an RVA pointing to a small structure called hint/name entry
        else:
            hint_name_offset = rva_to_offset(thunk)
            function_name = read_string(hint_name_offset + 2)
            if function_name in suspicious_apis:
                found_suspicious.append(function_name)
            # print(f"   function: {function_name}")
            imphash_parts.append(f"{dll_name_for_hash}.{function_name}".lower())
        
        j += 1
    
    i += 1

# All the collected dllname.functionname (and dllname.ordN) strings get joined with commas into one big string, then MD5-hashed
joined = ",".join(imphash_parts)
imphash = hashlib.md5(joined.encode()).hexdigest()
print(imphash)

print(f"suspicious APIs found: {found_suspicious}")