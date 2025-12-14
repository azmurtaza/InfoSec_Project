import lief
print(dir(lief))
try:
    print(f"bad_format: {lief.bad_format}")
except AttributeError:
    print("bad_format: MISSING")

try:
    print(f"read_out_of_bound: {lief.read_out_of_bound}")
except AttributeError:
    print("read_out_of_bound: MISSING")
