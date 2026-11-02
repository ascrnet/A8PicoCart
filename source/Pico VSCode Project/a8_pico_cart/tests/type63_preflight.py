"""Execute the linked Type63 raw-map integrity and SysTick latency admission.

The exact firmware ELF supplies every executed instruction. The timer advances
only for the three measured loads: one clock per CVR access, two for an SRAM
byte, and a declared additional cost for a flash byte. This tests the probe's
arithmetic, threshold and restoration; it does not measure RP2040 flash or
physical Atari timing. No instruction-wide tracing hook is installed.
"""
from pathlib import Path
import argparse
import binascii
import hashlib
import json
import os
import re
import struct
import time
from functools import lru_cache

from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_PC,
    UC_ARM_REG_PRIMASK,
)

PAYLOAD = 4 * 1024 * 1024
HEADER = Path(os.environ.get('A8_TEST_SOURCE', Path(__file__).resolve().parent.parent)) / 'type63_image.h'
HEADER_BYTES = HEADER.read_bytes()
def header_number(name):
    return int(re.search(r'^#define\s+' + name + r'\s+(0x[0-9a-fA-F]+|\d+)u?\s*$', HEADER_BYTES.decode(), re.M)[1],0)
FILE_PAGES, TABLE_BYTES, CACHE_CAPACITY_PAGES = 8193, 34816, 188
HEAD_CACHE_PAGES = header_number('TYPE63_HEAD_CACHE_PAGES')
INITIAL_CACHE_PAGES = header_number('TYPE63_INITIAL_CACHE_PAGES')
CACHE_PAGES = HEAD_CACHE_PAGES + INITIAL_CACHE_PAGES
COPY_BYTES = header_number('TYPE63_PROBE_COPY_BYTES')
SSI_MAX_EXTRA = header_number('TYPE63_SSI_MAX_EXTRA_CYCLES')
HEADER42_BYTES = HEADER.with_name('type42_image.h').read_bytes()
TYPE42_FILE_PAGES = int(re.search(r'^#define\s+TYPE42_FILE_PAGES\s+(\d+)u?\s*$',HEADER42_BYTES.decode(),re.M)[1])
BASE_SEAM_COUNT = header_number('TYPE63_BASE_SEAM_COUNT')
MAX_SEAM_COUNT = header_number('TYPE63_SEAM_COUNT')
SEAM_SLOT = TYPE42_FILE_PAGES - MAX_SEAM_COUNT
HINT_SLOT = SEAM_SLOT - 1
assert (BASE_SEAM_COUNT,MAX_SEAM_COUNT,SEAM_SLOT,HINT_SLOT)==(3,5,2044,2043)
SEAM_PAGES = (HEAD_CACHE_PAGES - 1, 8128, 8160)
assert CACHE_PAGES == 162 and SSI_MAX_EXTRA == 2
CSR, RVR, CVR, ICSR = 0xE000E010, 0xE000E014, 0xE000E018, 0xE000ED04
SSI_ENABLE, SSI_DIVIDER, SSI_STATUS = 0x18000008, 0x18000014, 0x18000028
SSI_CTRL0, SSI_CTRL1, SSI_SER = 0x18000000, 0x18000004, 0x18000010
SSI_DMACR, SSI_SPI_CTRL0, SSI_RX_SAMPLE = 0x1800004c, 0x180000f4, 0x180000f0
# RP2040 section4.10.6: legacy DFS[3:0] is inactive; actual parts may read7.
# Keep active DFS_32[20:16], frame format and transfer-mode guards strict.
SSI_DEFAULTS = {SSI_CTRL0:0x005f0307, SSI_CTRL1:0, SSI_ENABLE:1, SSI_SER:1,
                SSI_DMACR:0, SSI_SPI_CTRL0:0x00002022, SSI_RX_SAMPLE:1, SSI_DIVIDER:4, SSI_STATUS:6}
MASK, STOP = 0xFFFFFF, 0x10000000
OK, INTEGRITY, TIMER_BUSY, TOO_SLOW, SSI_MODE, SSI_TOO_SLOW = range(6)
RESULT_MASK = header_number('TYPE63_PREFLIGHT_STATUS_MASK')
REASON_SHIFT = header_number('TYPE63_PREFLIGHT_REGISTER_SHIFT')
assert RESULT_MASK == 0xff and REASON_SHIFT == 8
sha = lambda value: hashlib.sha256(value).hexdigest()


def fnv32(data):
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xFFFFFFFF
    return value


@lru_cache(maxsize=8)
def fingerprint(data):
    return sum(data) & 0xFFFFFFFF, fnv32(data)


def cached(page,extra_bank=0):
    return page < HEAD_CACHE_PAGES or 8128 <= page <= 8160 or bool(extra_bank and extra_bank*32<=page<=extra_bank*32+32)


def hint_bank(data):
    at=16+255*16384;record=data[at:at+20]
    if record[:8]!=b'A8C63HNT':return 0
    assert record[8:11]==bytes((1,20,1)) and 4<=record[11]<=253
    assert record[12:16]==bytes(4)
    assert int.from_bytes(record[16:20],'little')==binascii.crc32(record[:16])&0xffffffff
    return record[11]


def cache_slots(data,extra_bank=0):
    assignments={};uniform={};slot=0
    for page in range(FILE_PAGES):
        if not cached(page,extra_bank):continue
        block=data[page*512:(page+1)*512].ljust(512,b'\xff')
        value=block[0] if extra_bank and block in(bytes(512),b'\xff'*512) else None
        if value is not None and value in uniform:assignments[page]=uniform[value]
        else:
            assignments[page]=slot
            if value is not None:uniform[value]=slot
            slot+=1
    assert slot<=CACHE_CAPACITY_PAGES,('fixture cache exceeds fixed capacity',slot)
    return assignments,slot


class Probe:
    def __init__(self, elf_path, original, observed=None, extra=52,
                 csr=4, icsr=0, irq=0, no_flash=False, wrong_sum=False,
                 admission_checked=False, ssi_extra=2, ssi_overrides=None,
                 seam_physical_fault=None, extra_bank=0):
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        for address, size in (
            (0x10000000, 0x1000000), (0x13000000, 0x1000000),
            (0x20000000, 0x42000), (0x18000000, 0x1000),
            (0xD0000000, 0x1000), (0xE000E000, 0x1000),
        ):
            self.u.mem_map(address, size)
        with elf_path.open('rb') as stream:
            elf = ELFFile(stream)
            symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
            self.symbols = {s.name: s.entry.st_value for s in symbols}
            for segment in elf.iter_segments():
                if segment.header.p_type == 'PT_LOAD' and segment.header.p_filesz:
                    self.u.mem_write(segment.header.p_vaddr, segment.data())
        self.ram = self.symbols['cart_ram']
        assert self.ram + 131072 <= 0x20042000
        self.probe_source = self.symbols['type63_flash_probe_impl'] & ~1
        self.probe_size = next(s.entry.st_size for s in symbols if s.name == 'type63_flash_probe_impl')
        self.probe_copy = self.symbols['type42_pages'] + 256 * 4
        self.copy_bytes = COPY_BYTES
        assert self.probe_copy+self.copy_bytes<=self.symbols['type42_pages']+HINT_SLOT*4
        self.bus_source = self.symbols['type63_steady_loop'] & ~1
        self.bus_bytes = self.symbols['type63_steady_loop_end'] - self.bus_source
        assert 0x10000000 <= self.bus_source < 0x11000000
        assert self.bus_source % 4 == 0 and 0 < self.bus_bytes <= self.copy_bytes
        assert self.probe_copy + self.bus_bytes <= self.symbols['type42_pages'] + SEAM_SLOT * 4
        self.bus_memcpy_calls = []
        self.copy_entries = 0
        self.memcpy_calls = []
        assert 0x10000000 <= self.probe_source < 0x11000000
        assert 0x20000000 <= self.probe_copy < self.probe_copy + self.copy_bytes <= 0x20042000
        assert self.probe_source % 4 == self.probe_copy % 4 == 0
        assert 0 < self.probe_size <= self.copy_bytes
        # Respect ARM ELF mapping symbols: literal-pool words are data, not
        # instructions. No BL/BLX may require relocation outside the copied body.
        markers = sorted((s.entry.st_value & ~1, s.name[:2]) for s in symbols
                         if s.name.startswith(('$t', '$d')))
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
        limit = self.probe_source + self.probe_size
        boundaries = sorted({self.probe_source, limit} |
                            {at for at, kind in markers if self.probe_source < at < limit})
        for start, end in zip(boundaries, boundaries[1:]):
            kind = next((kind for at, kind in reversed(markers) if at <= start), '$t')
            if kind == '$t':
                for instruction in decoder.disasm(bytes(self.u.mem_read(start, end - start)), start):
                    assert instruction.mnemonic not in ('bl', 'blx'), ('external probe call', hex(instruction.address))
        self.data = original if observed is None else observed
        self.expected_sum, self.expected_hash = fingerprint(original[16:])
        self.observed_sum, self.observed_hash = fingerprint(self.data[16:])
        self.extra = extra
        self.ssi_extra = ssi_extra
        self.seam_physical_fault = seam_physical_fault
        self.extra_bank=extra_bank
        self.seam_pages=SEAM_PAGES+((extra_bank*32,extra_bank*32+32)if extra_bank else())
        assignments,self.cache_slot_count=cache_slots(self.data,extra_bank)
        self.cached_raw_pages=FILE_PAGES if no_flash else len(assignments)
        if no_flash:self.cache_slot_count=1
        self.divider_writes = 0
        self.no_flash = no_flash
        self.probing = False
        self.fast_active = False
        self.pages = []
        self.physical_seams = []
        slot = 0
        for page in range(FILE_PAGES):
            if no_flash:
                pointer = self.ram + TABLE_BYTES
                block = bytes(512)
            elif cached(page,extra_bank):
                pointer = self.ram + TABLE_BYTES + assignments[page] * 512
                slot += 1
                block = self.data[page * 512:(page + 1) * 512].ljust(512, b'\xff')
            else:
                pointer = 0x10800000 + ((page * 1031) % 8192) * 512
                # Exercise raw admission maps with both allocating and already
                # nonallocating pointers. Each observed flash byte must use13.
                if page % 257 == 0:
                    pointer += 0x03000000
                block = self.data[page * 512:(page + 1) * 512].ljust(512, b'\xff')
            self.u.mem_write(pointer, block)
            if pointer >> 24 == 0x10:
                self.u.mem_write(pointer + 0x03000000, block)
            self.pages.append(pointer)
        for seam, page in enumerate(self.seam_pages):
            pointer = 0x10800000 + ((page * 1031) % 8192) * 512
            block = bytearray(bytes(512) if no_flash else original[page*512:(page+1)*512])
            if seam_physical_fault and seam_physical_fault[0] == seam:
                block[seam_physical_fault[1]] ^= 1
            self.u.mem_write(pointer, bytes(block))
            self.u.mem_write(pointer+0x03000000, bytes(block))
            self.physical_seams.append(pointer if seam%2==0 else pointer+0x03000000)
        if no_flash:
            # Deliberately malformed but in-bounds raw map: all8193 entries
            # alias one zero SRAM sector. Matching SUM/FNV must not admit it.
            self.expected_sum = self.observed_sum = 0
            self.expected_hash = self.observed_hash = fingerprint(bytes(PAYLOAD))[1]
        else:
            assert slot == self.cached_raw_pages
        assert TABLE_BYTES + CACHE_CAPACITY_PAGES * 512 == 131072
        assert TABLE_BYTES + self.cache_slot_count * 512 <= 131072
        if not extra_bank and not no_flash:assert self.cache_slot_count==CACHE_PAGES
        self.normalized = [p + 0x03000000 if p >> 24 == 0x10 else p for p in self.pages]
        self.u.mem_write(self.ram, struct.pack('<8193I', *self.pages))
        self.u.mem_write(self.symbols['type42_pages'], bytes(256 * 4))
        self.u.mem_write(self.symbols['type42_pages']+HINT_SLOT*4,struct.pack('<6I',extra_bank,*self.physical_seams,*([0]*(MAX_SEAM_COUNT-len(self.physical_seams)))))
        self.word(self.symbols['type63_pages'], self.ram)
        self.word(self.symbols['type42_mapper_type'], 63)
        self.word(self.symbols['type42_file_pages'], FILE_PAGES)
        self.word(self.symbols['type42_bank_count'], 256)
        self.word(self.symbols['type42_payload_checksum'], self.expected_sum ^ int(wrong_sum))
        self.word(self.symbols['type63_payload_hash'], self.expected_hash)
        self.word(self.symbols['type63_admission_checked'], int(admission_checked))
        self.ssi_initial = dict(SSI_DEFAULTS)
        self.ssi_initial.update(ssi_overrides or {})
        self.initial_csr, self.initial_rvr, self.initial_divider = csr, 0x543210, self.ssi_initial[SSI_DIVIDER]
        self.control, self.reload, self.counter = csr, self.initial_rvr, 0x654321
        self.reload_pending = False
        for address, value in (
            (CSR, csr), (RVR, self.reload), (CVR, self.counter), (ICSR, icsr),
            *self.ssi_initial.items(),
        ):
            self.word(address, value)
        self.initial_irq = irq
        self.u.reg_write(UC_ARM_REG_PRIMASK, irq)
        self.payload_reads = self.flash_reads = self.sram_reads = self.reference_reads = 0
        self.word_reference_reads = self.register_reads = self.seam_reads = self.seam_compare_reads = 0
        self.timer_reads = self.wraps = self.wrapped_measurements = 0
        self.timer_pair = None
        self.reference_cycles = []
        self.word_reference_cycles = []
        self.register_cycles = []
        self.measurement_kind = None
        self.mmio_writes = []
        self.mmio_reads = []
        self.allocating_reads = self.flash_instructions = 0
        self.initial_memory = bytes(self.u.mem_read(self.ram, 131072))
        self.initial_seams = bytes(self.u.mem_read(self.symbols['type42_pages']+HINT_SLOT*4,24))
        self.u.hook_add(UC_HOOK_MEM_READ, self.timer_read, begin=0xE000E000, end=0xE000EFFF)
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.mmio_write, begin=0xE000E000, end=0xE000EFFF)
        self.u.hook_add(UC_HOOK_MEM_READ, self.ssi_read, begin=0x18000000, end=0x18000FFF)
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.mmio_write, begin=0x18000000, end=0x18000FFF)
        self.u.hook_add(UC_HOOK_MEM_READ, self.payload_read, begin=0x13000000, end=0x13FFFFFF)
        self.u.hook_add(UC_HOOK_MEM_READ, self.allocating_read, begin=0x10000000, end=0x10FFFFFF)
        self.u.hook_add(UC_HOOK_MEM_READ, self.payload_read,
                        begin=self.ram + TABLE_BYTES, end=self.ram + 131071)
        at = self.symbols['type63_payload_hash']
        self.u.hook_add(UC_HOOK_MEM_READ, self.reference_read, begin=at, end=at + 3)
        # Narrow code guards do not add a per-instruction hook to SRAM code.
        for first in (0x10000000, 0x13000000):
            self.u.hook_add(UC_HOOK_CODE, self.flash_execution, begin=first, end=first + 0xFFFFFF)
        self.u.hook_add(UC_HOOK_CODE, self.copied_entry,
                        begin=self.probe_copy, end=self.probe_copy)
        copy_service = self.symbols['__wrap_memcpy'] & ~1
        self.u.hook_add(UC_HOOK_CODE, self.sdk_memcpy,
                        begin=copy_service, end=copy_service)

    def word(self, address, value):
        self.u.mem_write(address, struct.pack('<I', value))

    def get(self, name):
        return struct.unpack('<I', self.u.mem_read(self.symbols[name], 4))[0]

    def advance(self, amount):
        if self.control & 1:
            if self.reload_pending:
                self.counter = self.reload
                self.reload_pending = False
            if self.counter < amount:
                self.wraps += 1
            self.counter = (self.counter - amount) & MASK

    def timer_read(self, emu, access, address, size, value, user):
        assert size == 4
        self.mmio_reads.append(address) if address != CVR else None
        if address == CVR:
            self.advance(1)
            self.word(CVR, self.counter)
            self.timer_reads += 1
            if self.timer_pair is None:
                self.timer_pair = self.counter
            else:
                measured = (self.timer_pair - self.counter) & MASK
                if self.timer_pair < self.counter:
                    self.wrapped_measurements += 1
                if self.measurement_kind == 'reference':
                    self.reference_cycles.append(measured)
                elif self.measurement_kind == 'word-reference':
                    self.word_reference_cycles.append(measured)
                elif self.measurement_kind == 'register':
                    self.register_cycles.append(measured)
                self.timer_pair = None
                self.measurement_kind = None

    def ssi_read(self, emu, access, address, size, value, user):
        assert size == 4
        self.mmio_reads.append(address)
        if self.timer_pair is not None:
            assert address == SSI_STATUS, ('unexpected timed SSI register',hex(address))
            self.advance(2 + self.ssi_extra)
            self.register_reads += 1
            self.measurement_kind = 'register'

    def mmio_write(self, emu, access, address, size, value, user):
        assert size == 4
        self.mmio_writes.append((address, value))
        if address == CSR:
            self.control = value & 7
        elif address == RVR:
            self.reload = value & MASK
        elif address == CVR:
            self.counter = 0
            self.reload_pending = True
        elif address == SSI_DIVIDER:
            self.divider_writes += 1
            self.fast_active = self.divider_writes == 1

    def reference_read(self, emu, access, address, size, value, user):
        if self.timer_pair is not None:
            assert address == self.symbols['type63_payload_hash']
            self.advance(2)
            if size == 1:
                self.reference_reads += 1
                self.measurement_kind = 'reference'
            else:
                assert size == 4
                self.word_reference_reads += 1
                self.measurement_kind = 'word-reference'

    def allocating_read(self, emu, access, address, size, value, user):
        self.allocating_reads += 1
        if self.probing and self.fast_active:
            raise AssertionError(('allocating flash read during probe', hex(address), size))

    def flash_execution(self, emu, address, size, user):
        self.flash_instructions += 1
        if self.probing and self.fast_active:
            raise AssertionError(('flash instruction during probe', hex(address)))

    def copied_entry(self, emu, address, size, user):
        assert address == self.probe_copy
        assert bytes(self.u.mem_read(address, self.copy_bytes)) == bytes(self.u.mem_read(self.probe_source, self.copy_bytes)), 'copied probe differs from linked ELF bytes'
        self.copy_entries += 1

    def sdk_memcpy(self, emu, address, size, user):
        # The SDK forwards this service to RP2040 boot ROM, which is not part
        # of the firmware ELF. Model its ABI only, before the fast divider;
        # neither wrapper/probe instructions nor the copied bytes are patched.
        assert not self.fast_active
        target, source, count = [self.u.reg_read(r) for r in
                                 (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        if self.probing:
            assert (target, source, count) == (self.probe_copy, self.probe_source, self.copy_bytes)
        else:
            # Preparing the exact linked map now installs the final bus loop
            # before ACK. Model this second legitimate SDK ROM service only;
            # do not skip installer code or admit an arbitrary memcpy tuple.
            assert self.active_call == 'type63_prepare_bus'
            assert (target, source, count) == (self.probe_copy, self.bus_source, self.bus_bytes)
            self.bus_memcpy_calls.append(dict(target=target, source=source, bytes=count))
        self.u.mem_write(target, bytes(self.u.mem_read(source, count)))
        self.memcpy_calls.append(dict(target=target, source=source, bytes=count))
        self.u.reg_write(UC_ARM_REG_PC, self.u.reg_read(UC_ARM_REG_LR))

    def payload_read(self, emu, access, address, size, value, user):
        assert size == 1
        if self.timer_pair is None:
            assert self.payload_reads == PAYLOAD and address >> 24 == 0x20
            at = self.seam_compare_reads
            assert at < self.seam_reads and at < len(self.seam_pages)*512
            page = self.seam_pages[at // 512]
            expected = self.pages[page] + at % 512
            assert address == expected, ('cached physical seam comparison',at,hex(address),hex(expected))
            self.seam_compare_reads += 1
            return
        if self.payload_reads == PAYLOAD:
            at = self.seam_reads
            assert at < len(self.seam_pages)*512, 'physical seam scan exceeded declared sectors'
            raw = self.physical_seams[at // 512]
            normalized = raw + 0x03000000 if raw >> 24 == 0x10 else raw
            expected = normalized + at % 512
            assert address == expected, ('physical seam/order mismatch',at,hex(address),hex(expected))
            self.advance(2 + self.extra)
            self.seam_reads += 1
            self.measurement_kind = 'seam'
            return
        file_offset = self.payload_reads + 16
        assert file_offset < PAYLOAD + 16, 'probe read beyond the complete CAR payload'
        expected = self.normalized[file_offset // 512] + file_offset % 512
        assert address == expected, ('raw sector/order mismatch', self.payload_reads, hex(address), hex(expected))
        flash = address >> 24 == 0x13
        self.advance(2 + (self.extra if flash else 0))
        self.payload_reads += 1
        self.flash_reads += int(flash)
        self.sram_reads += int(not flash)
        self.measurement_kind = 'payload'

    def call(self, name='type63_verify_fast_flash', budget=400000000):
        self.active_call = name
        self.probing = name == 'type63_verify_fast_flash'
        self.u.reg_write(UC_ARM_REG_SP, 0x20041000)
        self.u.reg_write(UC_ARM_REG_LR, STOP | 1)
        started = time.monotonic()
        self.u.emu_start(self.symbols[name] | 1, STOP, count=budget)
        assert self.u.reg_read(UC_ARM_REG_PC) == STOP, (name, 'execution budget exhausted')
        assert self.u.reg_read(UC_ARM_REG_SP) == 0x20041000, 'stack not restored'
        return bool(self.u.reg_read(UC_ARM_REG_R0)), time.monotonic() - started

    def check_restored(self, borrowed, full_scan=True, seams_complete=True):
        assert self.u.reg_read(UC_ARM_REG_PRIMASK) == self.initial_irq, 'interrupt mask changed'
        for address, expected in ((CSR, self.initial_csr), (RVR, self.initial_rvr), *self.ssi_initial.items()):
            assert struct.unpack('<I', self.u.mem_read(address, 4))[0] == expected, ('register not restored', hex(address))
        assert bytes(self.u.mem_read(self.ram, 131072)) == self.initial_memory, 'raw map/cache changed'
        assert bytes(self.u.mem_read(self.symbols['type42_pages']+HINT_SLOT*4,24)) == self.initial_seams, 'physical seam originals changed'
        if borrowed:
            assert self.copy_entries == 1, 'timed probe did not execute the exact copied body'
            assert len(self.memcpy_calls) == 1
            assert self.reference_reads == 64 and self.reference_cycles == [3] * 64
            assert self.word_reference_reads == self.register_reads == 64
            assert self.word_reference_cycles == [3] * 64
            assert self.register_cycles == [3 + self.ssi_extra] * 64
            assert self.payload_reads == (PAYLOAD if full_scan else 0)
            assert self.timer_reads == 2 * (self.payload_reads + self.seam_reads + 64*3)
            expected_sram = PAYLOAD if self.no_flash else self.cached_raw_pages * 512 - 16
            assert self.sram_reads == (expected_sram if full_scan else 0)
            assert self.flash_reads == (PAYLOAD - expected_sram if full_scan else 0)
            if full_scan:
                assert self.seam_reads == self.seam_compare_reads
                if seams_complete:assert self.seam_reads == len(self.seam_pages)*512
                else:assert 0 < self.seam_reads <= len(self.seam_pages)*512
            else:assert self.seam_reads == self.seam_compare_reads == 0
            assert self.timer_pair is None
            for address, values in ((CSR, [5, 0, self.initial_csr]),
                                    (RVR, [MASK, self.initial_rvr]),
                                    (CVR, [0, 0]), (SSI_ENABLE, [0, 1, 0, 1]),
                                    (SSI_DIVIDER, [2, self.initial_divider])):
                assert [v for a, v in self.mmio_writes if a == address] == values, ('register write sequence', hex(address))
        else:
            assert not self.mmio_writes, 'rejected probe changed timer/SSI registers'
            assert self.payload_reads == self.reference_reads == self.word_reference_reads == self.register_reads == self.seam_reads == self.timer_reads == 0


def exercise(elf, data, full, hinted_data=None):
    cases = []

    bypass = Probe(elf, data, admission_checked=True)
    original_tail = bytes(bypass.u.mem_read(bypass.probe_copy, bypass.copy_bytes))
    accepted, elapsed = bypass.call('type42_verify_fast_flash', 100000)
    assert accepted
    bypass.check_restored(False)
    assert not bypass.mmio_reads and not bypass.memcpy_calls and not bypass.copy_entries
    assert bypass.allocating_reads == bypass.flash_instructions == 0
    assert bytes(bypass.u.mem_read(bypass.probe_copy, bypass.copy_bytes)) == original_tail
    cases.append(dict(name='admitted-dispatcher-does-not-rescan', accepted=True,
                      payloadReads=0, probeCopies=0, timerAndSsiReads=0,
                      flashReadsAndInstructions=0, registersRestored=True))

    def run(name, accepted, status, borrowed=True, seams_complete=True, mismatch=None, fixture_data=None, **options):
        probe = Probe(elf, data if fixture_data is None else fixture_data, **options)
        result, elapsed = probe.call()
        assert result == accepted and probe.get('type63_preflight_result') == status, (name, result, probe.get('type63_preflight_result'))
        full_scan = borrowed and status != SSI_TOO_SLOW
        probe.check_restored(borrowed, full_scan=full_scan, seams_complete=seams_complete)
        expected_extra = (mismatch[1] if mismatch is not None else
                          options.get('ssi_extra',2) if status == SSI_TOO_SLOW else
                          options.get('extra',52) if borrowed and seams_complete else 0)
        assert probe.get('type63_flash_extra_cycles') == expected_extra
        row = dict(name=name, accepted=result, preflightResult=status, seconds=round(elapsed, 3),
                   payloadReads=probe.payload_reads, flashReads=probe.flash_reads,
                   cachedPayloadReads=probe.sram_reads, referenceReads=probe.reference_reads,
                   wordReferenceReads=probe.word_reference_reads,
                   timedSsiStatusReads=probe.register_reads,ssiBridgeExtraClocks=probe.ssi_extra,
                   physicalSeamReads=probe.seam_reads,cachedSeamComparisons=probe.seam_compare_reads,
                   extraCachedBank=probe.extra_bank,selectedRawCachePages=probe.cached_raw_pages,uniqueCacheSlots=probe.cache_slot_count,
                   physicalSeamPages=list(probe.seam_pages),cacheHintSlot=HINT_SLOT,seamOriginalSlot=SEAM_SLOT,
                   extraFlashCycles=probe.get('type63_flash_extra_cycles'),
                   timerWraps=probe.wraps, wrappedMeasurements=probe.wrapped_measurements,
                   copiedProbeEntries=probe.copy_entries,
                   probeFunctionBytes=probe.probe_size,
                   probeFunctionSha256=sha(bytes(probe.u.mem_read(probe.probe_source, probe.probe_size))),
                   probeSourceAddress=hex(probe.probe_source),
                   probeCopyAddress=hex(probe.probe_copy),
                   modeledSdkMemcpyCalls=probe.memcpy_calls,
                   expectedSum=probe.expected_sum, expectedFnv32=probe.expected_hash,
                   observedSum=probe.observed_sum, observedFnv32=probe.observed_hash,
                   initialInterruptMask=probe.initial_irq, registersRestored=True,
                   rawMapAndCacheUnmodified=True,ssiCtrlr0Readback=probe.ssi_initial[SSI_CTRL0])
        if mismatch is not None:
            offset,value=mismatch
            assert status & RESULT_MASK == SSI_MODE and status >> REASON_SHIFT == offset
            assert not probe.mmio_writes and probe.payload_reads == 0
            row['ssiModeFailure']=dict(registerOffset=offset,rawValue=value,
                                       resultCode=status & RESULT_MASK,packedResult=status)
        cases.append(row)
        print(json.dumps(row), flush=True)
        return probe

    good = run('52-extra-clocks-admitted', True, OK, extra=52, csr=4, irq=0)
    assert good.wrapped_measurements > 0, '24-bit timer wrap was not exercised'
    run('legacy-dfs-zero-readback-admitted',True,OK,
        ssi_overrides={SSI_CTRL0:0x005f0300})
    # Hardware reported F4=00002022. XIP_CMD is not part of the direct FIFO
    # protocol; the reader explicitly supplies A0 in every address/mode word.
    # Keep the SDK's A0 readback as a separate complete-payload control too.
    run('xip-command-a0-readback-admitted',True,OK,
        ssi_overrides={SSI_SPI_CTRL0:0xa0002022})
    run('53-extra-clocks-refused', False, TOO_SLOW, extra=53, csr=0, irq=1)
    # A cached admission bypass belongs only to the dispatcher. The direct
    # public verifier must still copy and rescan the full raw map, including
    # the owner's measured 50-extra-clock case after an earlier admission.
    run('admitted-direct-verifier-rescans-50-extra-clocks', True, OK, extra=50,
        csr=4, irq=0, admission_checked=True)
    for extra in (0,1):
        run('ssi-bridge-'+str(extra)+'-extra-clocks-admitted',True,OK,ssi_extra=extra)
    run('ssi-bridge-3-extra-clocks-refused',False,SSI_TOO_SLOW,ssi_extra=3)
    for name,address,value in (
        ('data-frame-width',SSI_CTRL0,0x00470307),
        ('transfer-mode',SSI_CTRL0,0x005f0007),
        ('frame-format',SSI_CTRL0,0x005f0317),
        ('receive-count',SSI_CTRL1,1),
        ('disabled',SSI_ENABLE,0),
        ('slave-select',SSI_SER,2),
        ('dma-enabled',SSI_DMACR,1),
        ('dummy-cycle-format',SSI_SPI_CTRL0,0xa0000022),
        ('rx-sample-delay',SSI_RX_SAMPLE,2),
        ('unapproved-divider',SSI_DIVIDER,6),
    ):
        offset=address-SSI_CTRL0
        overrides={address:value}
        if name=='frame-format':
            # Both registers are bad; the reported first failure must remain C0.
            overrides[SSI_CTRL1]=1
        rejected=run('ssi-whitelist-'+name+'-refused',False,
                     SSI_MODE|(offset<<REASON_SHIFT),borrowed=False,
                     mismatch=(offset,value),ssi_overrides=overrides)
        assert not rejected.mmio_writes and rejected.get('type63_flash_extra_cycles')==value
    for name, control, icsr, irq in (
        ('running-counter', 5, 0, 0), ('timer-interrupt-enabled', 2, 0, 1),
        ('pending-systick', 4, 1 << 26, 0), ('active-systick', 0, 15, 1),
    ):
        run(name, False, TIMER_BUSY, borrowed=False, csr=control, icsr=icsr, irq=irq)
    prepared = Probe(elf, data)
    prepared.call('type63_prepare_bus', 1000000)
    assert len(prepared.bus_memcpy_calls) == 1, 'prepare must install the exact bus loop once'
    assert bytes(prepared.u.mem_read(prepared.probe_copy, prepared.bus_bytes)) == bytes(prepared.u.mem_read(prepared.bus_source, prepared.bus_bytes))
    prepared.initial_memory = bytes(prepared.u.mem_read(prepared.ram, 131072))
    tagged=struct.unpack('<I',prepared.u.mem_read(prepared.symbols['type42_pages'],4))[0]
    assert tagged==prepared.ram|1,'prepared fully cached bank must retain its SRAM tag'
    prepared.call('type63_prepare_bus',1000000)
    assert len(prepared.bus_memcpy_calls) == 1, 'idempotent prepare must not copy the bus loop again'
    assert bytes(prepared.u.mem_read(prepared.ram,131072))==prepared.initial_memory,'tagged prepare not idempotent'
    result, elapsed = prepared.call()
    assert not result and prepared.get('type63_preflight_result') == INTEGRITY
    prepared.check_restored(False)
    cases.append(dict(name='prepared-map-refused', accepted=False, preflightResult=INTEGRITY,
                      payloadReads=0, registersRestored=True, preparedMapAndCacheUnmodified=True,
                      taggedCachedBankRejected=True,taggedPreparationIdempotent=True,
                      preAckBusInstallerCopies=prepared.bus_memcpy_calls,
                      preAckBusInstallerCopyExact=True,secondPrepareCopiedNothing=True))
    if full:
        run('wrong-expected-sum-refused', False, INTEGRITY, wrong_sum=True)
        changed = bytearray(data)
        swap_at = next(at for at in range(512, len(data) - 1)
                       if not cached(at // 512) and at % 512 < 511 and changed[at] != changed[at + 1])
        changed[swap_at], changed[swap_at + 1] = changed[swap_at + 1], changed[swap_at]
        swapped = run('sum-preserving-flash-swap-refused', False, INTEGRITY, observed=bytes(changed))
        assert swapped.expected_sum == swapped.observed_sum
        assert swapped.expected_hash != swapped.observed_hash
        changed = bytearray(data)
        changed[512 + 31] ^= 1
        run('cached-payload-corruption-refused', False, INTEGRITY, observed=bytes(changed))
        run('matching-zero-sram-only-map-refused', False, INTEGRITY, no_flash=True)
        for seam,offset in ((0,0),(1,17),(2,511)):
            run('physical-seam-'+str(seam)+'-corruption-refused',False,INTEGRITY,
                seam_physical_fault=(seam,offset),seams_complete=False)
        changed=bytearray(data)
        changed[SEAM_PAGES[0]*512+31]^=1
        run('cached-seam-corruption-refused',False,INTEGRITY,
            observed=bytes(changed),seams_complete=False)
        run('already-divider2-restored-after-full-scan',True,OK,
            ssi_overrides={SSI_DIVIDER:2})
    if hinted_data is not None:
        bank=hint_bank(hinted_data);assert bank==24,'focused qualification requires bank24 hint'
        hinted=run('hinted-whole-bank24-admitted',True,OK,fixture_data=hinted_data,extra_bank=bank)
        assert hinted.cached_raw_pages==195 and hinted.cache_slot_count<=188
        assert hinted.seam_reads==hinted.seam_compare_reads==5*512
        hinted.call('type63_prepare_bus',1000000)
        tag=struct.unpack('<I',hinted.u.mem_read(hinted.symbols['type42_pages']+bank*4,4))[0]
        assert tag==(hinted.ram+bank*136)|1
        saved=bytes(hinted.u.mem_read(hinted.ram,131072));copies=len(hinted.bus_memcpy_calls)
        hinted.call('type63_prepare_bus',1000000)
        assert bytes(hinted.u.mem_read(hinted.ram,131072))==saved and len(hinted.bus_memcpy_calls)==copies==1
        cases[-1].update(extraBankTaggedCached=True,hintedPrepareIdempotent=True,allFivePhysicalSeamsCompared=True)
        for seam,offset in((3,0),(4,511)):
            run('hinted-extra-seam-'+str(seam)+'-corruption-refused',False,INTEGRITY,
                fixture_data=hinted_data,extra_bank=bank,seam_physical_fault=(seam,offset),seams_complete=False)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--car', type=Path)
    parser.add_argument('--hint-car',type=Path,help='Append whole-bank24 hinted-map admission and both additional physical seam refusals')
    parser.add_argument('--report', type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--quick', action='store_true', help='Default:52/53 boundary, admitted50 rescan and non-clobbering guards')
    mode.add_argument('--full', action='store_true', help='Also isolate SUM, FNV, cached corruption and no-flash rejection')
    args = parser.parse_args()
    source_bytes = Path(__file__).read_bytes()
    elf_bytes = args.elf.read_bytes()
    if args.car:
        data = args.car.read_bytes()
    else:
        payload = bytes((i * 37 ^ i >> 8 ^ i >> 14 ^ i >> 20) & 255 for i in range(PAYLOAD))
        data = b'CART' + struct.pack('>III', 63, sum(payload), 0) + payload
    assert len(data) == PAYLOAD + 16 and data[:4] == b'CART'
    assert struct.unpack('>I', data[4:8])[0] == 63
    assert sum(data[16:]) == struct.unpack('>I', data[8:12])[0]
    hinted_data=args.hint_car.read_bytes() if args.hint_car else None
    if hinted_data is not None:
        assert len(hinted_data)==PAYLOAD+16 and sum(hinted_data[16:])==struct.unpack('>I',hinted_data[8:12])[0]
    cases = exercise(args.elf, data, args.full,hinted_data)
    assert args.elf.read_bytes() == elf_bytes
    assert Path(__file__).read_bytes() == source_bytes, 'test source changed during execution'
    if args.car:
        assert args.car.read_bytes() == data, 'owner cartridge changed'
    report = dict(result='PASS', mode='full' if args.full else 'quick',
                  firmwareElfSha256=sha(elf_bytes), testSourceSha256=sha(source_bytes),
                  ownerCarSha256=sha(data) if args.car else None,
                  hintedCarSha256=sha(hinted_data)if hinted_data is not None else None,
                  hintedCasesExecuted=hinted_data is not None,hintSlot=HINT_SLOT,seamSlots=list(range(SEAM_SLOT,TYPE42_FILE_PAGES)),
                  type42HeaderSha256=sha(HEADER42_BYTES),rawFilePages=FILE_PAGES, expandedTableBytes=TABLE_BYTES,
                  immutableCachePages=CACHE_PAGES,cacheCapacityPages=CACHE_CAPACITY_PAGES,
                  usedCartRamBytes=TABLE_BYTES+CACHE_PAGES*512,fixedCartRamBytes=131072,
                  expectedFnv32=fingerprint(data[16:])[1], allPayloadBytesRead=PAYLOAD,
                  exactLinkedCodeExecuted=True, noInstructionWideHook=True,
                  sdkRomMemcpyModeled=True, probeInstructionsUnmodified=True,
                  frozenHeaderSha256=sha(HEADER_BYTES),
                  copiedProbe=dict(copyBoundBytes=COPY_BYTES, alignedToBytes=4,
                                   copyAndFunctionBytesBoundAtEntry=True,
                                   externalCallsAllowed=False,
                                   storage='inactive type42_pages[256..2042] tail; hint2043 and five originals2044..2048 retained'),
                  timingModel=dict(cvrReadClocks=1, sramByteClocks=2,
                                   flashAdditionalPass=52, flashAdditionalFail=53,
                                   admittedDirectRescanAdditionalClocks=50,
                                   sramWordClocks=2,ssiBridgeAcceptedExtraClocks=[0,1,2],
                                   ssiBridgeRefusedExtraClocks=3,
                                   counterBits=24, cacheReuse=False,
                                   measuredHardwareLatency=False),
                  physicalTimingQualified=False, ownerCarUnmodified=True, cases=cases)
    report['ssiModeContract']=dict(defaultCtrlr0=SSI_DEFAULTS[SSI_CTRL0],
                                  defaultSpiCtrlr0=SSI_DEFAULTS[SSI_SPI_CTRL0],
                                  ignoredLegacyDfsMask=15,activeCtrlr0Mask=0x017ffff0,
                                  activeSpiCtrlr0Mask=0x0007fb3f,
                                  ignoredXipCommandMask=0xff000000,
                                  explicitDirectFifoModeByte=0xa0,
                                  resultCodeMask=RESULT_MASK,registerOffsetShift=REASON_SHIFT,
                                  failedRawValueField='type63_flash_extra_cycles',
                                  legacyZeroFullPayloadControl=True,
                                  xipCommandA0FullPayloadControl=True)
    assert HEADER.read_bytes()==HEADER_BYTES and HEADER.with_name('type42_image.h').read_bytes()==HEADER42_BYTES,'test headers changed during execution'
    if args.hint_car:assert args.hint_car.read_bytes()==hinted_data,'hinted owner cartridge changed'
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
