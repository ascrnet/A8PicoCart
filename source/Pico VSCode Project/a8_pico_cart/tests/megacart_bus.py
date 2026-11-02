"""Execute linked CAR30 firmware against a fragmented, immutable ROM map.

Run ELF [--car ORIGINAL.CAR] [--report REPORT.JSON]. The synthetic mapper
witness always runs; an optional unchanged owner image runs independently.
This checks compiled logic and bus release, not physical Atari timing.
"""
from pathlib import Path
import argparse
import hashlib
import json
import random
import struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_PC

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('elf', type=Path)
p.add_argument('--car', type=Path)
p.add_argument('--report', type=Path)
args = p.parse_args()
sha = lambda data: hashlib.sha256(data).hexdigest()
elf_bytes = args.elf.read_bytes()
source_hash = sha(Path(__file__).read_bytes())
PHI, RW, CCTL, S4, S5 = (1 << bit for bit in (22, 23, 21, 24, 25))
RD4, RD5, DATA = 1 << 26, 1 << 27, 255 << 13
RD = RD4 | RD5
PAYLOAD = 262144
FILE_PAGES, HALF_BANKS = 513, 32
PERIOD, FALL = 300, 200


def run_fixture(file_data, label):
    assert len(file_data) == PAYLOAD + 16 and file_data[:4] == b'CART'
    assert struct.unpack('>I', file_data[4:8])[0] == 30
    assert sum(file_data[16:]) == struct.unpack('>I', file_data[8:12])[0]
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    for address, size in ((0x10000000, 0x1000000), (0x13000000, 0x1000000),
                          (0x20000000, 0x42000), (0x18000000, 0x1000),
                          (0xD0000000, 0x1000)):
        uc.mem_map(address, size)
    with args.elf.open('rb') as stream:
        elf = ELFFile(stream)
        symbols = {s.name: s.entry.st_value for s in elf.get_section_by_name('.symtab').iter_symbols()}
        for segment in elf.iter_segments():
            if segment.header.p_type == 'PT_LOAD' and segment.header.p_filesz:
                uc.mem_write(segment.header.p_vaddr, segment.data())
    for name in ('type42_clock_start',):
        assert 0x20000000 <= symbols[name] < 0x20042000, (name, 'must reside in SRAM')
    loop_source = symbols['megacart_steady_loop'] & ~1
    loop_bytes = symbols['megacart_steady_loop_end'] - loop_source
    loop_ram = symbols['type42_pages'] + FILE_PAGES * 4
    assert 0x10000000 <= loop_source < 0x11000000, 'steady loop source stays in flash'
    assert loop_bytes % 4 == 0 and 0 < loop_bytes <= (2049 - FILE_PAGES) * 4
    for name, value in (('type42_file_pages', FILE_PAGES), ('type42_bank_count', HALF_BANKS),
                        ('type42_bank_mask', HALF_BANKS - 1), ('type42_initial_bank', 0),
                        ('type42_mapper_type', 30), ('type42_payload_checksum', sum(file_data[16:]))):
        uc.mem_write(symbols[name], struct.pack('<I', value))
    pages, cache_slot = [], 0
    for page in range(FILE_PAGES):
        if page < 17 or page >= FILE_PAGES - 239:
            pointer = symbols['cart_ram'] + cache_slot * 512
            cache_slot += 1
        elif 128 <= page <= 160:
            # Both halves of 16 KiB bank four have direct flash bases.
            pointer = 0x10400000 + page * 512
        else:
            pointer = 0x10800000 + ((page * 1031) % 4096) * 512
        chunk = file_data[page * 512:(page + 1) * 512].ljust(512, b'\xff')
        uc.mem_write(pointer, chunk)
        if 0x10000000 <= pointer < 0x11000000:
            uc.mem_write(pointer + 0x03000000, chunk)
        pages.append(pointer)
    assert cache_slot == 256, 'fixed 128 KiB immutable cache'
    bases = []
    for half in range(HALF_BANKS):
        first = half * 16
        direct = all(pages[first + j] == pages[first] + j * 512 for j in range(17))
        bases.append(pages[first] + 16 if direct else 0)
    assert bases[0] and not bases[1] and not bases[2]
    assert bases[8] and bases[9] and bases[30] and bases[31]
    uc.mem_write(symbols['type42_pages'], struct.pack('<513I', *pages))
    uc.mem_write(symbols['type42_bank_base'], struct.pack('<32I', *bases))

    def call(name, budget):
        uc.reg_write(UC_ARM_REG_SP, 0x20041000)
        uc.reg_write(UC_ARM_REG_LR, 0x10000001)
        uc.emu_start(symbols[name] | 1, 0x10000000, count=budget)
        assert uc.reg_read(UC_ARM_REG_PC) == 0x10000000, (name, 'instruction budget exhausted')

    bad_address = pages[17] + 0x03000000
    original = bytes(uc.mem_read(bad_address, 1))
    for corrupt in (False, True):
        uc.mem_write(bad_address, bytes([original[0] ^ int(corrupt)]))
        uc.mem_write(0x18000014, struct.pack('<I', 4))
        call('type42_verify_fast_flash', 40000000)
        assert uc.reg_read(UC_ARM_REG_R0) == int(not corrupt), 'preflight corruption rejection'
        assert struct.unpack('<I', uc.mem_read(0x18000014, 4))[0] == 4, 'menu divider restoration'
    uc.mem_write(bad_address, original)
    call('type42_prepare_bus', 100000)
    call('type42_prepare_bus', 100000)

    cases = []
    bank, enabled = 0, True

    def control(address, value=0, write=True, abort=None, never_high=False):
        nonlocal bank, enabled
        previous = enabled
        if write and not abort and not never_high:
            bank, enabled = value & 15, not bool(value & 128)
        cases.append(dict(pins=S4 | S5 | 0x1500 | address | (value << 13) | (0 if write else RW),
                          bank=bank, enabled=enabled, previous=previous, control=True,
                          write=write, value=value, abort=abort, never_high=never_high))

    def read(address, write=False, unselected=False, fault=None, early=False):
        pins = CCTL | (0 if write else RW) | (S5 if address < 8192 else S4) | (address & 8191)
        if unselected:
            pins |= S4 | S5
        cases.append(dict(pins=pins, bank=bank, enabled=enabled, previous=enabled,
                          control=False, fault=fault, early=early))

    # Initial bank, both windows and the header seams precede any bank write.
    for offset in (0, 495, 496, 511, 512, 8191, 8192, 8687, 8688, 8703, 8704, 16383):
        read(offset)
    for value in range(256):
        # A permutation visits every D5 address and every written data value.
        control((value * 37 + 11) & 255, value)
        for offset in (0, 495, 496, 8191, 8192, 8687, 8688, 16383):
            read(offset)
        read(37, write=True)
        read(8192 + 37, write=True)
        read(17, unselected=True)
        control(value ^ 128, value ^ 0x8f, write=False)
    # All D5 reads, including bit7 addresses, retain a selected/off bank.
    for off in (False, True):
        control(0x92, 5 | (128 if off else 0))
        for address in range(256):
            control(address, address ^ 0xff, write=False)
        read(3)
        read(8195)
    # Neither incomplete writes nor writes held entirely during PHI2 low latch.
    control(0, 3)
    for abort in ('deselect', 'read'):
        for value in (0, 7, 0x80, 0x8f):
            control(0x77, value, abort=abort)
            read(0)
            read(8192)
    for value in (0, 15, 128, 255):
        control(0x66, value, never_high=True)
        read(0)
        read(8192)
    # Fragmented, direct flash and cached reads reject stale requests on each
    # window, including S4->S5 transitions with unchanged low address bits.
    for selected_bank in (1, 4, 15):
        control(0, selected_bank)
        for offset in (0x1555, 0x3555):
            for early in (False, True):
                for fault in ('address', 'select', 'deselect', 'write'):
                    read(offset, fault=fault, early=early)
                    read(offset)
    rng = random.Random(30)
    for _ in range(256):
        control(rng.randrange(256), rng.randrange(256))
        read(rng.randrange(16384))
    control(0, 0)
    read(16383)

    index, steps, checked = 0, 0, 0
    output, oe = 0, 0
    started, sram_only, overlay_entered = False, False, False
    faulted, early_faults, seen = set(), set(), set()
    uncached_reads, prefetch_drives = 0, 0

    def pins_now():
        case, phase = cases[index], steps % PERIOD
        if phase >= FALL:
            # Different data at the falling sample catches latching after PHI2.
            return CCTL | S4 | S5 | RW | (0xa6 << 13)
        pins = case['pins']
        if case['control'] and case['write'] and phase < 155:
            pins = (pins & ~DATA) | ((case['value'] ^ 0x8f) << 13)
        if case.get('abort') and phase >= 120:
            pins |= CCTL if case['abort'] == 'deselect' else RW
        if index in faulted:
            fault = case['fault']
            if fault == 'address':
                pins = (pins & ~8191) | ((pins + 1) & 8191)
            elif fault == 'select':
                pins ^= S4 | S5
            elif fault == 'deselect':
                pins |= S4 | S5
            elif fault == 'write':
                pins &= ~RW
        if 50 <= phase < FALL and not case.get('never_high'):
            pins |= PHI
        return pins

    def valid_read(pins):
        return pins & (CCTL | RW) == CCTL | RW and pins & (S4 | S5) in (S4, S5)

    def expected_byte(pins, selected):
        offset = (8192 if pins & S4 else 0) + (pins & 8191)
        return file_data[16 + selected * 16384 + offset]

    def is_payload_address(address):
        return (0x13000000 <= address < 0x14000000 or
                symbols['cart_ram'] <= address < symbols['cart_ram'] + 131072)

    def hook_code(emu, address, size, user):
        nonlocal index, steps, checked, overlay_entered
        if sram_only:
            assert 0x20000000 <= address < 0x20042000, ('bus instruction outside SRAM', hex(address))
        if loop_ram <= address < loop_ram + loop_bytes:
            overlay_entered = True
        if overlay_entered:
            assert loop_ram <= address < loop_ram + loop_bytes, ('steady execution left its copied loop', hex(address))
        if not started:
            return
        steps += 1
        if steps % PERIOD == 0:
            index += 1
            if index == len(cases):
                emu.emu_stop()
                return
        phase, case = steps % PERIOD, cases[index]
        if phase == 125:
            expected_enabled = case['previous'] if case['control'] else case['enabled']
            assert output & RD == (RD if expected_enabled else 0), (index, 'early RD4/RD5 state', case)
            pins = pins_now()
            if valid_read(pins) and case['enabled']:
                assert oe & DATA == DATA, (index, 'missing ROM data', case)
                assert (output >> 13) & 255 == expected_byte(pins, case['bank']), (index, 'wrong ROM byte')
            else:
                assert not oe & DATA, (index, 'unexpected bus drive', case)
            checked += 1
        if phase == 250:
            assert output & RD == (RD if case['enabled'] else 0), (index, 'latched RD4/RD5 state', case)
            assert not oe & DATA, (index, 'data bus not released at end of cycle')

    def hook_read(emu, access, address, size, value, user):
        nonlocal started, uncached_reads
        if sram_only:
            assert not 0x10000000 <= address < 0x11000000, 'cached XIP or flash literal after SSI change'
        if started and is_payload_address(address):
            if 0x13000000 <= address < 0x14000000:
                uncached_reads += 1
            case = cases[index]
            if index in early_faults:
                assert valid_read(pins_now()), (index, 'obsolete fetch must not start', case)
                offset = (8192 if pins_now() & S4 else 0) + (pins_now() & 8191)
                file_offset = 16 + case['bank'] * 16384 + offset
                pointer = pages[file_offset // 512]
                if 0x10000000 <= pointer < 0x11000000:
                    pointer += 0x03000000
                assert address == pointer + file_offset % 512, (index, 'fetch used stale address/select')
            if case.get('fault') and not case['early'] and index not in faulted:
                faulted.add(index)
        if address == 0xD0000004:
            started = True
            pins = pins_now()
            if valid_read(pins):
                seen.add(index)
            emu.mem_write(address, struct.pack('<I', pins))

    def hook_write(emu, access, address, size, value, user):
        nonlocal output, oe, sram_only, prefetch_drives
        if address == 0x18000008 and value == 0:
            sram_only = True
        elif address == 0xD0000010:
            output = value
        elif address == 0xD0000014:
            output |= value
        elif address == 0xD0000018:
            output &= ~value
        elif address == 0xD0000028:
            oe &= ~value
            if started and index in seen and cases[index].get('early') and index not in faulted:
                faulted.add(index)
                early_faults.add(index)
        elif address == 0xD0000024:
            oe |= value
            if started and value & DATA:
                pins, case = pins_now(), cases[index]
                assert valid_read(pins) and case['enabled'], (index, 'invalid ROM drive', case)
                assert (output >> 13) & 255 == expected_byte(pins, case['bank']), (index, 'stale byte driven')
                assert output & RD == RD, (index, 'ROM drive changed an enable output')
                if steps % PERIOD < 50:
                    prefetch_drives += 1

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_READ, hook_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_write)
    uc.reg_write(UC_ARM_REG_SP, 0x20041000)
    uc.reg_write(UC_ARM_REG_LR, 0x10000101)
    uc.emu_start(symbols['emulate_type42'] | 1, 0, count=len(cases) * PERIOD + 20000)
    assert checked == len(cases), (checked, len(cases), 'bus budget exhausted')
    assert overlay_entered, 'compiled dispatcher never entered the copied SRAM loop'
    assert len(faulted) == 48 and len(early_faults) == 24, (faulted, early_faults)
    stale = struct.unpack('<I', uc.mem_read(symbols['type42_stale_reads'], 4))[0]
    assert stale == 24, ('stale fetch counter', stale)
    assert uncached_reads > 100 and prefetch_drives > 100
    converted = lambda ptr: ptr + 0x03000000 if 0x10000000 <= ptr < 0x11000000 else ptr
    assert struct.unpack('<513I', uc.mem_read(symbols['type42_pages'], 513 * 4)) == tuple(map(converted, pages))
    assert struct.unpack('<32I', uc.mem_read(symbols['type42_bank_base'], 32 * 4)) == tuple(map(converted, bases))
    assert bytes(uc.mem_read(loop_ram, loop_bytes)) == bytes(uc.mem_read(loop_source, loop_bytes)), 'SRAM loop copy'
    unused = (2049 - FILE_PAGES) * 4 - loop_bytes
    assert bytes(uc.mem_read(loop_ram + loop_bytes, unused)) == bytes(unused), 'table tail beyond code changed'
    return dict(label=label, imageSha256=sha(file_data), compiled_bus_cases=checked,
                copied_loop_bytes=loop_bytes, copied_loop_sram_address=hex(loop_ram),
                bus_flash_reads_bypass_cache=uncached_reads,
                rom_drives_before_phi2_high=prefetch_drives,
                obsolete_fetches_prevented_before_load=len(early_faults), stale_fetches_discarded=stale)


payload = bytes((i * 37 ^ i >> 8 ^ i >> 13 ^ i >> 16) & 255 for i in range(PAYLOAD))
fixtures = [run_fixture(b'CART' + struct.pack('>III', 30, sum(payload), 0) + payload, 'synthetic')]
car_hash = None
if args.car:
    original_car = args.car.read_bytes()
    car_hash = sha(original_car)
    fixtures.append(run_fixture(original_car, 'owner-image'))
    assert sha(args.car.read_bytes()) == car_hash, 'owner image changed'
assert sha(args.elf.read_bytes()) == sha(elf_bytes), 'linked firmware changed during checks'
assert sha(Path(__file__).read_bytes()) == source_hash, 'test source changed during checks'
report = dict(result='PASS', car_type=30, payload_bytes=PAYLOAD, startup_bank=0,
              compiled_bus_cases=sum(row['compiled_bus_cases'] for row in fixtures), fixtures=fixtures,
              fast_flash_preflight_and_corruption_rejection=True,
              all_control_write_addresses_and_values=True, late_write_data_latched=True,
              both_windows_enabled_and_disabled=True, reads_preserve_bank_and_enable=True,
              direct_fragmented_and_cached_halves=True, header_seams_preserved=True,
              incomplete_control_writes_do_not_latch=True,
              obsolete_fetches_prevented_before_load=sum(row['obsolete_fetches_prevented_before_load'] for row in fixtures),
              bus_flash_reads_bypass_cache=sum(row['bus_flash_reads_bypass_cache'] for row in fixtures),
              sram_only_after_flash_clock_change=True, inactive_page_table_tail_reused=True,
              fixed_cache_bytes=131072,
              firmwareElfSha256=sha(elf_bytes), testSourceSha256=source_hash,
              physical_timing_validated=False, full_game_acceptance=False)
if car_hash:
    report['carImageSha256'] = car_hash
if args.report:
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
