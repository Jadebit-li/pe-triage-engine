import struct
import datetime
from collections import Counter
import math

path = "sample/putty.exe"

with open(path, 'rb') as f:
    data = f.read()

# DOS header
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

machine = file_header[0]
number_of_sections = file_header[1]
time_date_stamp = file_header[2]
pointer_to_symbol_table = file_header[3]
number_of_symbols = file_header[4]
size_of_optional_header = file_header[5]
characteristics = file_header[6]

build_date = datetime.datetime.fromtimestamp(time_date_stamp, datetime.UTC)

address_of_entry_point = struct.unpack('<I', data[e_lfanew+40:e_lfanew+44])[0]
section_table_start = e_lfanew + 24 + size_of_optional_header

def entropy(data):
    counts = Counter(data)
    total = len(data)
    
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

for i in range(number_of_sections):
    entry_offset = section_table_start + (i * 40)
    # print(hex(entry_offset))
    
    section_entry = struct.unpack('<8sIIIIIIHHI', data[entry_offset:entry_offset+40])
    name = section_entry[0]
    name = name.rstrip(b'\x00').decode('ascii')
    size_of_raw_data = section_entry[3]
    pointer_to_raw_data = section_entry[4]

    section_bytes = data[pointer_to_raw_data : pointer_to_raw_data + size_of_raw_data]
    section_entropy = entropy(section_bytes)

    print(f"{name}: raw_size={hex(size_of_raw_data)}, entropy={section_entropy:.2f}")

print(f"entropy of the entire executable: {entropy(data):.2f}")


