import struct
import datetime

path = "sample/putty.exe"

with open(path, 'rb') as f:
    data = f.read()

# DOS header
e_magic = struct.unpack('<H', data[0:2])[0]
e_lfanew = struct.unpack('<I', data[60:64])[0]

print(hex(e_magic))
print(hex(e_lfanew))

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

print(hex(machine))
print(number_of_sections)
print(build_date)
print(size_of_optional_header)