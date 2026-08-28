import struct
import datetime

path = "sample/putty.exe"

with open(path, 'rb') as f:
    data = f.read()

e_magic = struct.unpack('<H', data[0:2])[0]
e_lfanew = struct.unpack('<I', data[60:64])[0]

print(hex(e_magic))
print(hex(e_lfanew))

pe_signature = data[e_lfanew:e_lfanew + 4]

if pe_signature == b'PE\x00\x00':
    print("Valid PE signature found")
else:
    print("NOT a valid PE file")


# machine_types = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}

machine = struct.unpack('<H', data[e_lfanew+4:e_lfanew+6])[0]
number_of_sections = struct.unpack('<H', data[e_lfanew+6:e_lfanew+8])[0]
time_date_stamp = struct.unpack('<I', data[e_lfanew+8:e_lfanew+12])[0]

build_date = datetime.datetime.fromtimestamp(time_date_stamp, datetime.UTC)
print(build_date)

print(hex(machine))
print(number_of_sections)

