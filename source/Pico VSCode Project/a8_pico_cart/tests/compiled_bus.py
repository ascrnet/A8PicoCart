"""Execute the actual compiled ARM bus handler with mocked SIO/SSI registers.
This verifies logic, not RP2040 / flash / Atari cycle timing.
Requires unicorn and pyelftools; pass the linked firmware ELF path.
"""
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC


def option_value(name, default=None):
    for position, argument in enumerate(sys.argv[2:], 2):
        if argument.startswith(name + '='):
            return argument.split('=', 1)[1]
        if argument == name:
            assert position + 1 < len(sys.argv), 'Missing value for ' + name
            return sys.argv[position + 1]
    return default


preflight_limit = int(option_value('--preflight-limit', '40000000'))
assert 0 < preflight_limit <= 40000000, 'Preflight remains finite and bounded at 40 million instructions'
baseline_elf = option_value('--baseline-elf')

mpe = "--mpe" in sys.argv
car_type = next((int(arg.split("=", 1)[1]) for arg in sys.argv[2:]
                 if arg.startswith("--car-type=")), 42)
assert car_type in (42, 75, 109, 110, 112) and (not mpe or car_type == 42)
dcart = car_type == 112
payload_bytes = {42: 1048576, 75: 1048576, 109: 262144, 110: 524288, 112: 524288}[car_type]
file_pages = payload_bytes // 512 + 1
bank_count = payload_bytes // 8192
bank_mask = bank_count - 1
initial_bank = 127 if car_type == 42 else 0
native42 = car_type in (42, 75) and not mpe
head_pages = (239 if native42 else 1) if car_type in (42, 75) else 17
cache_pages = 240 if mpe else 224 if dcart else 256
uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
uc.mem_map(0x10000000, 0x1000000)
uc.mem_map(0x20000000, 0x42000)
uc.mem_map(0x18000000, 0x1000)
uc.mem_map(0xD0000000, 0x1000)
with open(sys.argv[1], "rb") as stream:
    elf = ELFFile(stream)
    symbols = {s.name: s.entry.st_value for s in elf.get_section_by_name(".symtab").iter_symbols()}
    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_LOAD" and segment.header.p_filesz:
            uc.mem_write(segment.header.p_vaddr, segment.data())

assert 0x20000000 <= symbols["type42_bus_loop"] < 0x20042000
if "type42_clock_start" in symbols:
    assert 0x20000000 <= symbols["type42_clock_start"] < 0x20042000
file_data = bytes((i * 37 ^ i >> 8 ^ i >> 13) & 255 for i in range(payload_bytes + 16))
for name, value in (("type42_file_pages", file_pages), ("type42_bank_count", bank_count),
                    ("type42_bank_mask", bank_mask), ("type42_initial_bank", initial_bank)):
    if name in symbols:
        uc.mem_write(symbols[name], struct.pack("<I", value))
    else:
        assert car_type == 42, "Older firmware only supports type42"
if "type42_mapper_type" in symbols:
    uc.mem_write(symbols["type42_mapper_type"], struct.pack("<I", car_type))
else:
    assert not dcart, "DCART needs its distinct mapper mode"
if dcart:
    dcart_loop_source = symbols["dcart_steady_loop"] & ~1
    dcart_loop_bytes = symbols["dcart_steady_loop_end"] - dcart_loop_source
    dcart_loop_ram = symbols["type42_pages"] + file_pages * 4
    assert 0x10000000 <= dcart_loop_source < 0x11000000, "DCart source copied while SSI is at menu speed"
    assert file_pages == 1025 and dcart_loop_ram % 4 == 0
    assert dcart_loop_bytes % 4 == 0 and 0 < dcart_loop_bytes <= (2049 - file_pages) * 4
    assert dcart_loop_ram + dcart_loop_bytes <= symbols["type42_pages"] + 2049 * 4
page_pointers = []
cache_slot = 0
for page in range(file_pages):
    if page < head_pages or page >= file_pages - (cache_pages - head_pages):
        pointer = symbols["cart_ram"] + cache_slot * 512
        cache_slot += 1
    elif 16 * 16 <= page <= 17 * 16:
        # One direct flash bank exercises conversion of the base table too.
        pointer = 0x10400000 + page * 512
    else:
        pointer = 0x10800000 + ((page * 1031) % 4096) * 512
    uc.mem_write(pointer, file_data[page * 512:(page + 1) * 512].ljust(512, b"\xff"))
    page_pointers.append(pointer)
uc.mem_write(symbols["type42_pages"], struct.pack("<" + str(file_pages) + "I", *page_pointers))
bank_bases = []
for bank in range(bank_count):
    first = bank * 16
    contiguous = all(page_pointers[first + j] == page_pointers[first] + j * 512 for j in range(17))
    bank_bases.append(page_pointers[first] + 16 if contiguous else 0)
uc.mem_write(symbols["type42_bank_base"], struct.pack("<" + str(bank_count) + "I", *bank_bases))
if dcart:
    assert cache_slot == 224
    mirror = b"".join(file_data[16 + bank * 8192 + 0x1500:16 + bank * 8192 + 0x1600]
                      for bank in range(64))
    assert len(mirror) == 16384
    uc.mem_write(symbols["cart_ram"] + 114688, mirror)

# Execute the production fast-flash verifier, including divider restoration
# and a deliberately corrupt uncached byte. No cycle/timing model is claimed.
uc.mem_map(0x13000000, 0x1000000)
for page, pointer in enumerate(page_pointers):
    if 0x10000000 <= pointer < 0x11000000:
        uc.mem_write(pointer + 0x03000000,
                     file_data[page * 512:(page + 1) * 512].ljust(512, b"\xff"))
uc.mem_write(symbols["type42_payload_checksum"], struct.pack("<I", sum(file_data[16:])))
bad_address = next(p for p in page_pointers if 0x10000000 <= p < 0x11000000) + 0x03000000
original = bytes(uc.mem_read(bad_address, 1))
for corrupt in (False, True):
    uc.mem_write(bad_address, bytes([original[0] ^ (1 if corrupt else 0)]))
    uc.mem_write(0x18000014, struct.pack("<I", 4))
    uc.reg_write(UC_ARM_REG_SP, 0x20041000)
    uc.reg_write(UC_ARM_REG_LR, 0x10000001)
    uc.emu_start(symbols["type42_verify_fast_flash"] | 1, 0x10000000, count=preflight_limit)
    assert uc.reg_read(UC_ARM_REG_PC) == 0x10000000, 'Preflight instruction budget exhausted'
    assert uc.reg_read(UC_ARM_REG_R0) == (0 if corrupt else 1), "fast flash verification"
    assert struct.unpack("<I", uc.mem_read(0x18000014, 4))[0] == 4, "menu divider not restored"
uc.mem_write(bad_address, original)

# Native CAR42 retains allocating XIP; all other routes convert both tables.
# The real load_file decision is covered separately by compiled_loader.py.
# Run shared preparation twice only for routes which actually use it.
for _ in range(0 if native42 else 2):
    uc.reg_write(UC_ARM_REG_SP, 0x20041000)
    uc.reg_write(UC_ARM_REG_LR, 0x10000001)
    uc.emu_start(symbols["type42_prepare_bus"] | 1, 0x10000000, count=100000)

PHI = 1 << 22
RW = 1 << 23
CCTL = 1 << 21
S4 = 1 << 24
S5 = 1 << 25
RD5 = 1 << 27
DATA = 255 << 13
cases = []
expected_bank, enabled = initial_bank, True
response_mode = False
reply = bytes([1]) + bytes((i * 19) & 255 for i in range(1,8192))

def read(address, **kwargs):
    active = enabled and not kwargs.get("write") and not kwargs.get("unselected")
    pins = CCTL | S4 | address
    if not kwargs.get("write"):
        pins |= RW
    if kwargs.get("unselected"):
        pins |= S5
    cases.append({"pins": pins, "data": (reply[address] if response_mode else file_data[16 + expected_bank * 8192 + address]) if active else None,
                  "enabled": enabled, "fault": kwargs.get("fault"), "bank": expected_bank,
                  "fault_before_fetch": kwargs.get("fault_before_fetch", False)})

def control(address, write, **kwargs):
    global expected_bank, enabled, response_mode
    response_mode = False
    if mpe and 0xe0 <= address < 0xf0: address = 0x80
    if not dcart or write:
        expected_bank, enabled = address & bank_mask, not bool(address & 128)
    data = file_data[16 + expected_bank * 8192 + 0x1500 + address] if dcart and not write else None
    cases.append({"pins": S4 | S5 | (0 if write else RW) | 0x1500 | address | (kwargs.get("value", 0) << 13),
                  "data": data, "enabled": enabled, "control": True, "d5_read": dcart and not write,
                  "bank": expected_bank, "fault": kwargs.get("fault"),
                  "hold_phi2_low": kwargs.get("hold_phi2_low", False),
                  "fault_before_fetch": kwargs.get("fault_before_fetch", False)})

read(0x1fff)  # Verify the mapper's initial bank before any control access.
for write in (False, True):
    for bank in range(128):
        control(bank, write)
        for address in (0, 495, 496, 511, 512, 4095, 8191):
            read(address)
        read(0x123, write=True)
        read(0x123, unselected=True)
        control(bank | 128, write)
        read(0x123)  # Even a spurious S5 select must not drive while disabled.
rng = random.Random(42)
for _ in range(1024):
    control(rng.randrange(128), bool(rng.getrandbits(1)))
    read(rng.randrange(8192))
if dcart:
    # Reads in every D5 address must retain bank/RD5, including addresses with
    # bit7 set. Writes alias both address bit6 values and ignore their data.
    for bank in range(64):
        for high_bits in (0, 0x40, 0x80, 0xc0):
            control(bank | high_bits, True, value=(bank * 37 + high_bits) & 255)
            for address in (0, 0x3f, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xef, 0xf0, 0xff):
                control(address, False)
            read(0x1500); read(0x15ff)
    # Check all 256 mirror offsets across all three storage representations.
    for bank in (0, 3, 16, 63):
        control(bank, True)
        for address in range(256):
            control(address, False)
        control(bank | 0x80, True)
        for address in range(256):
            control(address, False)
        read(0x1555)
control(3, True)
read(37, fault="address")
read(38)
read(39, fault="deselect")
read(40)
read(41, fault="write")
read(42)
for bank in (3, 16, bank_count - 1):  # fragmented flash, direct flash, direct SRAM
    control(bank, True)
    for fault in ("address", "deselect", "write"):
        read(0x1555, fault=fault, fault_before_fetch=True)
if dcart:
    # D5F0 crosses a file-sector boundary because the CAR header adds 16 bytes.
    # Abort stale D5 mirror fetches on address, control deselection and writes,
    # including an otherwise disabled 8K window.
    for bank in (3, 16, 63):
        control(bank | 0x80, True)
        for fault in ("address", "deselect", "write", "phi2"):
            control(0xef, False, fault=fault)
            control(bank | 0x80, True)
            control(0xf0, False)
            control(0xef, False, fault=fault, fault_before_fetch=True)
            control(bank | 0x80, True)
            control(0xf0, False)
        # PHI2 falls while the selected address/RW/CCTL stay unchanged: the
        # held data output must release without changing the selected bank.
        control(0xf0, False, hold_phi2_low=True)
        control(0xf0, False)


if mpe:
    # The response is outside the reduced immutable cache, as on hardware.
    uc.mem_write(symbols["cart_ram"]+122880, reply)
    command = 2 if '--ego' in sys.argv else 1
    if '--native' in sys.argv: command=0x11
    parameters = bytes([37,0x91,0xb2,0x34,0x12,27,97,110,10,2,0x45,0x23,1,0x55,0xaa])
    for address,value in [*enumerate(parameters,0xe0),(0xef,command)]:
        if address==0xef:
            enabled=True
            response_mode=True
        cases.append({"pins":S4|S5|0x1500|address|(value<<13),"data":None,
                      "enabled":enabled,"control":True,"late_write":True})
    for address in (0,1,8,11,31,32,495,496,511,512,4095,8191):
        read(address)
    # Busy submission cannot overwrite the in-flight parameters.
    for address in (0xe0,0xec,0xef):
        cases.append({"pins":S4|S5|0x1500|address|(99<<13),"data":None,"enabled":True,"control":True})
    read(8)
    control(127,True)
    read(8191)

index = 0
steps = 0
started = False
output = 0
oe = 0
checked = 0
prefetch_drives = 0
faulted = set()
request_seen = set()
early_faults = set()
obsolete_fetches = set()
discarded_fetch_cases = set()
uncached_bus_reads = 0
allocating_bus_reads = 0
d5_external_reads = 0
d5_sram_reads = 0
dcart_overlay_entered = False
PERIOD = 240

def pins_now():
    case = cases[index]
    phase = steps % PERIOD
    if phase >= 150:
        return CCTL | S4 | S5 | RW
    pins = case["pins"]
    # 6502 write data need not be valid at the beginning of PHI2 high.
    # Present a different value until late in the high phase. On the falling
    # edge the bus goes idle immediately, so only the final high sample is valid.
    if case.get("late_write") and phase < 115:
        pins = (pins & ~DATA) | (0xee << 13)
    if index in faulted:
        if case["fault"] == "address":
            pins = (pins & ~8191) | ((pins + 1) & 8191)
        elif case["fault"] == "deselect":
            pins |= CCTL if case.get("d5_read") else S5
        elif case["fault"] == "write":
            pins &= ~RW
    phi2_high = 50 <= phase < 150
    if case.get("hold_phi2_low") and phase >= 100:
        phi2_high = False
    if index in faulted and case["fault"] == "phi2":
        phi2_high = False
    return pins | (PHI if phi2_high else 0)

def hook_code(emu, address, size, user):
    global index, steps, checked, dcart_overlay_entered
    if not started:
        return
    assert 0x20000000 <= address < 0x20042000, ("instruction fetched outside SRAM during bus emulation", hex(address))
    if dcart and dcart_loop_ram <= address < dcart_loop_ram + dcart_loop_bytes:
        dcart_overlay_entered = True
    steps += 1
    if steps % PERIOD == 0:
        index += 1
        if index == len(cases):
            emu.emu_stop()
            return
    if steps % PERIOD == 125:
        case = cases[index]
        expected = case["data"]
        if case.get("fault") == "address":
            expected = file_data[16 + case["bank"] * 8192 + ((case["pins"] + 1) & 8191)]
        elif case.get("fault") or case.get("hold_phi2_low"):
            expected = None
        if expected is None:
            assert not oe & DATA, (index, "unexpected bus drive", oe, case)
        elif dcart and case.get("fault") == "address" and not oe & DATA:
            # A rejected mirror fetch may consume the remainder of PHI2.
            # Every subsequent drive is checked against the new address below;
            # the following ordinary mirror cycle proves service resumes.
            pass
        else:
            assert oe & DATA == DATA, (index, "no ROM data", case)
            assert (output >> 13) & 255 == expected, (index, "wrong ROM data", output, expected)
        assert bool(output & RD5) == case["enabled"], (index, "RD5", output, case)
        checked += 1
    if dcart and steps % PERIOD == 40 and cases[index].get("d5_read"):
        assert not oe & DATA, (index, "D5 mirror drove before PHI2 high", cases[index])

def hook_read(emu, access, address, size, value, user):
    global started, uncached_bus_reads, allocating_bus_reads, d5_external_reads, d5_sram_reads
    if started:
        if 0x10000000 <= address < 0x11000000:
            assert native42, "Only native CAR42 may allocate XIP data"
            allocating_bus_reads += 1
        if 0x13000000 <= address < 0x14000000:
            uncached_bus_reads += 1
            if dcart and cases[index].get("d5_read"):
                d5_external_reads += 1
        if dcart and cases[index].get("d5_read") and symbols["cart_ram"] + 114688 <= address < symbols["cart_ram"] + 131072:
            d5_sram_reads += 1
        in_rom = 0x13000000 <= address < 0x14000000 or native42 and 0x10000000 <= address < 0x11000000
        in_cache = symbols["cart_ram"] <= address < symbols["cart_ram"] + 131072
        if (in_rom or in_cache) and index in early_faults:
            # Starting an obsolete fetch is allowed: its byte must be rejected
            # by the mandatory post-fetch GPIO validation before any drive.
            case = cases[index]
            current_pointer = None
            if case["fault"] == "address":
                offset = 16 + case["bank"] * 8192 + ((case["pins"] + 1) & 8191)
                pointer = page_pointers[offset >> 9]
                if not native42 and 0x10000000 <= pointer < 0x11000000:
                    pointer += 0x03000000
                current_pointer = pointer + (offset & 511)
                if dcart and case.get("d5_read"):
                    current_pointer = symbols["cart_ram"] + 114688 + case["bank"] * 256 + ((case["pins"] + 1) & 255)
            if address != current_pointer:
                obsolete_fetches.add(index)
                discarded_fetch_cases.add(index)
    if address == 0xD0000004:
        started = True
        pins = pins_now()
        if valid_read(pins):
            request_seen.add(index)
        emu.mem_write(address, struct.pack("<I", pins))
        # Inject AFTER the first captured request, BEFORE mandatory validation.
        # Do not depend on a redundant per-read OE_CLR instruction existing.
        if index in request_seen and index not in faulted and cases[index]["fault_before_fetch"]:
            faulted.add(index)
            early_faults.add(index)
    elif started and cases[index].get("fault") and index not in faulted:
        in_rom = 0x13000000 <= address < 0x14000000 or native42 and 0x10000000 <= address < 0x11000000
        in_cache = symbols["cart_ram"] <= address < symbols["cart_ram"] + 131072
        if (in_rom or in_cache) and not cases[index]["fault_before_fetch"]:
            faulted.add(index)
            discarded_fetch_cases.add(index)

def hook_write(emu, access, address, size, value, user):
    global output, oe, prefetch_drives
    if address == 0xD0000010:
        output = value
    elif address == 0xD0000014:
        output |= value
    elif address == 0xD0000018:
        output &= ~value
    elif address == 0xD0000028:
        oe &= ~value
    elif address == 0xD0000024:
        oe |= value
        if started and value & DATA:
            pins = pins_now()
            assert valid_read(pins), (index, "invalid ROM drive", hex(pins))
            expected = cases[index]["data"]
            if index in faulted:
                assert cases[index]["fault"] == "address"
                expected = file_data[16 + cases[index]["bank"] * 8192 + (pins & 8191)]
            assert (output >> 13) & 255 == expected, (index, "stale byte driven", expected, output)
            if steps % PERIOD < 50:
                prefetch_drives += 1

def valid_read(pins):
    if not pins & RW:
        return False
    if dcart and not pins & CCTL:
        return bool(pins & PHI)
    return pins & (CCTL | S5 | RW) == CCTL | RW

uc.hook_add(UC_HOOK_CODE, hook_code)
uc.hook_add(UC_HOOK_MEM_READ, hook_read)
uc.hook_add(UC_HOOK_MEM_WRITE, hook_write, begin=0xD0000000, end=0xD0000FFF)
uc.reg_write(UC_ARM_REG_SP, 0x20041000)
uc.reg_write(UC_ARM_REG_LR, 0x10000101)
if mpe:
    uc.reg_write(UC_ARM_REG_R0,symbols["type42_pages"])
    uc.reg_write(UC_ARM_REG_R1,symbols["type42_bank_base"])
    output=RD5
    uc.mem_write(0x18000014,struct.pack("<I",2))
uc.emu_start(symbols["mpe_bus_loop" if mpe else "emulate_type42"] | 1, 0, count=6000000 if dcart else 3000000)
assert checked == len(cases), (checked, len(cases))
stale = struct.unpack("<I", uc.mem_read(symbols["type42_stale_reads"], 4))[0]
# R4 retains every R1 stale-counter update, including selected successors.
counted_discards = discarded_fetch_cases
assert stale == len(discarded_fetch_cases), (stale, discarded_fetch_cases)
assert len(faulted) == (36 if dcart else 12) and len(early_faults) == (21 if dcart else 9), (stale, faulted, early_faults)
assert prefetch_drives > 500, prefetch_drives
assert (allocating_bus_reads if native42 else uncached_bus_reads) > 1000
assert not (uncached_bus_reads if native42 else allocating_bus_reads), "Wrong native flash alias"
if dcart:
    assert d5_external_reads == 0, "D5 mirror must never start a blocking external read"
    assert d5_sram_reads > 1000, d5_sram_reads
    assert dcart_overlay_entered, "Actual DCart execution never entered the SRAM table-tail overlay"
    assert bytes(uc.mem_read(dcart_loop_ram, dcart_loop_bytes)) == bytes(uc.mem_read(dcart_loop_source, dcart_loop_bytes)), "Dcart copied code/literals differ"
    tail = (2049 - file_pages) * 4 - dcart_loop_bytes
    assert bytes(uc.mem_read(dcart_loop_ram + dcart_loop_bytes, tail)) == bytes(tail), "Dcart changed table tail beyond its bounded overlay"
def converted(pointer):
    return pointer + 0x03000000 if not native42 and 0x10000000 <= pointer < 0x11000000 else pointer
assert struct.unpack("<" + str(file_pages) + "I", uc.mem_read(symbols["type42_pages"], file_pages * 4)) == tuple(map(converted, page_pointers))
assert struct.unpack("<" + str(bank_count) + "I", uc.mem_read(symbols["type42_bank_base"], bank_count * 4)) == tuple(map(converted, bank_bases))
if mpe:
    assert bytes(uc.mem_read(symbols["mpe_registers"],15)) == parameters
    assert bytes(uc.mem_read(symbols["mpe_registers"]+15,1)) == bytes([command])


def profile_native_paths(elf_path):
    """Count executed instructions with fixed GPIO, independent of PERIOD.

    XIP reads are instantaneous in Unicorn. These are instruction counts, not
    CPU cycles, flash latency, Atari deadlines, or electrical timing results.
    The complete changing-request guards above remain the safety qualification.
    """
    result = []
    targets = [('S5_A1F7', 0x1f7, False), ('S5_A200', 0x200, False)]
    if dcart:
        targets += [('D5_EF', 0x15ef, True), ('D5_F0', 0x15f0, True)]
    for representation in ('direct_sram', 'direct_flash', 'fragmented_flash'):
        for target_name, offset, mirror in targets:
            machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
            for base, count in ((0x10000000, 0x1000000), (0x13000000, 0x1000000),
                                (0x20000000, 0x42000), (0x18000000, 0x1000),
                                (0xd0000000, 0x1000)):
                machine.mem_map(base, count)
            with Path(elf_path).open('rb') as stream:
                linked = ELFFile(stream)
                names = {entry.name: entry.entry.st_value
                         for entry in linked.get_section_by_name('.symtab').iter_symbols()}
                for segment in linked.iter_segments():
                    if segment.header.p_type == 'PT_LOAD' and segment.header.p_filesz:
                        machine.mem_write(segment.header.p_vaddr, segment.data())
            addresses = []
            for page in range(17):
                if representation == 'direct_sram':
                    pointer = names['cart_ram'] + page * 512
                elif representation == 'direct_flash':
                    pointer = (0x10400000 if native42 else 0x13400000) + page * 512
                else:
                    pointer = (0x10800000 if native42 else 0x13800000) + ((page * 1031) % 4096) * 512
                machine.mem_write(pointer, file_data[page * 512:(page + 1) * 512])
                addresses.append(pointer)
            machine.mem_write(names['type42_pages'], struct.pack('<17I', *addresses))
            machine.mem_write(names['type42_bank_base'], struct.pack(
                '<I', 0 if representation == 'fragmented_flash' else addresses[0] + 16))
            for name, number in (('type42_file_pages', file_pages),
                                 ('type42_bank_count', bank_count),
                                 ('type42_bank_mask', bank_mask),
                                 ('type42_initial_bank', 0), ('type42_mapper_type', car_type)):
                machine.mem_write(names[name], struct.pack('<I', number))
            if dcart:
                machine.mem_write(names['cart_ram'] + 114688, file_data[16 + 0x1500:16 + 0x1600])
            pins = S4 | S5 | RW | PHI | offset if mirror else CCTL | S4 | RW | PHI | offset
            expected_byte = file_data[16 + offset]
            state = dict(started=False, instructions=0, gpio_reads=0, fetch=None,
                         gpio_after_fetch=0, output=0, driven=False)

            def code_hook(emu, address, size, user):
                if state['started']:
                    assert 0x20000000 <= address < 0x20042000, 'Profile left SRAM bus code'
                    state['instructions'] += 1

            def read_hook(emu, access, address, size, value, user):
                if address == 0xd0000004:
                    state['started'] = True
                    state['gpio_reads'] += 1
                    if state['fetch'] is not None:
                        state['gpio_after_fetch'] += 1
                    # This request is externally held fixed. Its progress is
                    # deliberately unrelated to emulated instruction count.
                    emu.mem_write(address, struct.pack('<I', pins))
                elif state['started'] and (0x13000000 <= address < 0x14000000 or
                       native42 and 0x10000000 <= address < 0x11000000 or
                       names['cart_ram'] <= address < names['cart_ram'] + 131072):
                    assert state['fetch'] is None, 'Stable read performed multiple payload fetches'
                    state['fetch'] = state['instructions'] + 1
                    state['gpio_before_fetch'] = state['gpio_reads']

            def write_hook(emu, access, address, size, value, user):
                if address == 0xd0000010:
                    state['output'] = value
                elif address == 0xd0000014:
                    state['output'] |= value
                elif address == 0xd0000018:
                    state['output'] &= ~value
                elif address == 0xd0000024 and value & DATA:
                    assert state['fetch'] is not None
                    assert state['gpio_after_fetch'] > 0, 'No post-fetch GPIO validation sample'
                    assert (state['output'] >> 13) & 255 == expected_byte, 'Profile drove wrong byte'
                    state['driven'] = True
                    emu.emu_stop()

            machine.hook_add(UC_HOOK_CODE, code_hook)
            machine.hook_add(UC_HOOK_MEM_READ, read_hook)
            machine.hook_add(UC_HOOK_MEM_WRITE, write_hook)
            machine.reg_write(UC_ARM_REG_SP, 0x20041000)
            machine.reg_write(UC_ARM_REG_LR, 0x10000101)
            machine.mem_write(0x18000014, struct.pack('<I', 4))
            machine.emu_start(names['emulate_type42'] | 1, 0, count=10000)
            assert state['driven'], (representation, target_name, 'No response within fixed profile budget')
            result.append(dict(representation=representation, target=target_name,
                               first_sample_to_drive_instructions=state['instructions'] + 1,
                               first_sample_to_payload_load_instructions=state['fetch'],
                               gpio_samples_before_payload_load=state['gpio_before_fetch'],
                               post_fetch_gpio_samples=state['gpio_after_fetch'],
                               expected=expected_byte))
    return result


path_profile = None
if not mpe:
    current_rows = profile_native_paths(sys.argv[1])
    path_profile = dict(scope='Actual compiled instructions with externally fixed GPIO; instantaneous XIP reads',
                        physical_timing_validated=False, cpu_cycles_measured=False,
                        firmware_elf_sha256=hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest(),
                        current=current_rows)
    if baseline_elf:
        previous_rows = profile_native_paths(baseline_elf)
        deltas = []
        for current_row, previous_row in zip(current_rows, previous_rows):
            assert (current_row['representation'], current_row['target']) == (
                previous_row['representation'], previous_row['target'])
            saved = previous_row['first_sample_to_drive_instructions'] - current_row['first_sample_to_drive_instructions']
            assert saved >= 0, ('Native response instruction path grew', current_row, previous_row)
            deltas.append(dict(representation=current_row['representation'], target=current_row['target'],
                               instructions_saved=saved))
        baseline_hash = hashlib.sha256(Path(baseline_elf).read_bytes()).hexdigest()
        if baseline_hash != path_profile['firmware_elf_sha256']:
            assert any(row['instructions_saved'] > 0 for row in deltas), 'No measured instruction-path reduction'
        path_profile.update(baseline_elf_sha256=baseline_hash, baseline=previous_rows,
                            comparison=deltas, no_profile_path_increased=True)
print(json.dumps({"result": "PASS", "mpe_interface":mpe, "car_type":car_type,
                  "payload_bytes":payload_bytes,"compiled_bus_cases": checked,
                  "fast_flash_preflight_and_corruption_rejection": True,
                  "preflight_instruction_limit": preflight_limit,
                  "preflight_return_checked": True,
                  "startup_bank": initial_bank, "all_legacy_control_addresses_read_and_write": not mpe,
                  "rom_drives_before_phi2_high": prefetch_drives,
                  "obsolete_address_deselect_and_write_not_driven": True,
                  "bus_flash_reads_bypass_cache": uncached_bus_reads,
                  "bus_flash_reads_allocating_xip": allocating_bus_reads,
                  "native42_allocating_alias_only": native42,
                  "cache_head_pages": head_pages,
                  "direct_and_fragmented_pointer_conversion": True,
                  "early_request_changes_exercised": len(early_faults),
                  "obsolete_fetches_prevented_before_load": len(early_faults - obsolete_fetches),
                  "obsolete_fetches_safely_discarded": len(obsolete_fetches),
                  "stale_fetches_discarded": len(discarded_fetch_cases),
                  "stale_debug_counter": stale,
                  "dcart_d5_external_reads": d5_external_reads,
                  "dcart_d5_sram_mirror_reads": d5_sram_reads,
                  "normal_cache_pages": cache_pages,
                  "dcart_copied_loop_bytes": dcart_loop_bytes if dcart else None,
                  "dcart_overlay_sram_address": hex(dcart_loop_ram) if dcart else None,
                  "dcart_overlay_execution_checked": dcart_overlay_entered if dcart else None,
                  "selected_read_successor_retries_without_counter": len(discarded_fetch_cases - counted_discards),
                  "prefetch_load_elision_required": False,
                  "late_write_data_latched":mpe,
                  "dcart_d5_reads_preserve_bank_and_window":dcart,
                  "dcart_all_d5_writes_select_by_address_not_data":dcart,
                  "dcart_d5_mirror_works_while_window_disabled":dcart,
                  "dcart_header_offset_sector_boundary":dcart,
                  "dcart_phi2_fetch_abort_and_held_data_release":dcart,
                  "native_read_path_profile": path_profile,
                  "physical_timing_validated": False}))
