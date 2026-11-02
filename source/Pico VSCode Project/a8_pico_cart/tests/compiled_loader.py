"""Exercise compiled load_file routing with synthetic files and mocked FatFs IO.

The real FatFs/image parser is covered separately by host_type42.c. This test
catches integration mistakes such as internal mapper-ID collisions and failure
to run the Type42 preflight. The additional pointer-routing cases execute the
real prepare function, while explicitly doubling IO, image admission and the
preflight boundary. No cache timing or physical bus behavior is modeled.
Pass the firmware ELF (feature enabled or disabled).
"""
import json
import struct
import sys
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP

uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
uc.mem_map(0x10000000, 0x100000)
uc.mem_map(0x20000000, 0x42000)
segments = []
with open(sys.argv[1], "rb") as stream:
    elf = ELFFile(stream)
    symbols = {s.name: s.entry.st_value for s in elf.get_section_by_name(".symtab").iter_symbols()}
    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_LOAD" and segment.header.p_filesz:
            data = segment.data()
            segments.append((segment.header.p_vaddr, data))
            uc.mem_write(segment.header.p_vaddr, data)

enabled = "type42_load_image" in symbols
mock_names = ("f_mount", "f_open", "f_close", "f_read", "f_lseek", "type42_load_image", "type42_load_standard_image", "type63_load_image", "type61_load_image",
              "type42_verify_fast_flash", "type42_prepare_bus", "mpe_load_image", "native_load_image", "__wrap_memcpy", "__wrap_memset")
mock_addresses = {symbols[name] & ~1: name for name in mock_names if name in symbols}
state = {}

def hook(emu, address, size, user):
    name = mock_addresses.get(address)
    if not name:
        return
    state["calls"].append(name)
    result = 0
    if name == "f_lseek":
        state["offset"]=emu.reg_read(UC_ARM_REG_R1)
    elif name == "f_read":
        amount = min(emu.reg_read(UC_ARM_REG_R2), len(state["file"]) - state["offset"])
        if amount:
            emu.mem_write(emu.reg_read(UC_ARM_REG_R1), state["file"][state["offset"]:state["offset"] + amount])
        emu.mem_write(emu.reg_read(UC_ARM_REG_R3), struct.pack("<I", amount))
        state["offset"] += amount
    elif name in ("type42_load_image", "type42_load_standard_image", "type63_load_image", "type61_load_image", "mpe_load_image", "native_load_image"):
        if name == "type42_load_standard_image":
            assert emu.reg_read(UC_ARM_REG_R3) == state["car_type"]
        result = int(state["image_ok"])
    elif name == "type42_verify_fast_flash":
        result = int(state["flash_ok"])
    elif name in ("__wrap_memcpy", "__wrap_memset"):
        destination = emu.reg_read(UC_ARM_REG_R0)
        source = emu.reg_read(UC_ARM_REG_R1)
        count = emu.reg_read(UC_ARM_REG_R2)
        data = bytes(emu.mem_read(source, count)) if name.endswith("memcpy") else bytes([source & 255]) * count
        emu.mem_write(destination, data)
        result = destination
    emu.reg_write(UC_ARM_REG_R0, result)
    emu.reg_write(UC_ARM_REG_PC, emu.reg_read(UC_ARM_REG_LR))

uc.hook_add(UC_HOOK_CODE, hook)
cases = 0

def check(car_type, payload_size, expected, image_ok=True, flash_ok=True, extension="CAR", magic=b"CART"):
    global cases, state
    state = {"file": magic + struct.pack(">III", car_type, 0, 0) + bytes(payload_size),
             "offset": 0, "calls": [], "image_ok": image_ok, "flash_ok": flash_ok, "car_type": car_type}
    # Use unused scratch-X memory for the name, outside the actual stack.
    uc.mem_write(0x20040000, ("TEST."+extension+"\0").encode())
    uc.reg_write(UC_ARM_REG_R0, 0x20040000)
    uc.reg_write(UC_ARM_REG_SP, 0x20042000)
    uc.reg_write(UC_ARM_REG_LR, 0x10000001)
    uc.emu_start(symbols["load_file"] | 1, 0x10000000, count=1000000)
    assert uc.reg_read(UC_ARM_REG_R0) == expected, (car_type, expected, uc.reg_read(UC_ARM_REG_R0))
    calls = state["calls"]
    assert "f_close" in calls
    assert calls[-1] == "f_mount"  # unmount before returning to the menu
    if car_type in (30, 42, 61, 63, 75, 109, 110, 112) and enabled and extension=="CAR":
        expected_loader = "type61_load_image" if car_type == 61 else "type63_load_image" if car_type == 63 else "type42_load_image" if car_type == 42 else "type42_load_standard_image"
        assert calls.count(expected_loader) == 1
        assert calls.count("type42_verify_fast_flash") == int(image_ok)
        assert calls.count("type42_prepare_bus") == int(image_ok and flash_ok and car_type not in (42, 75))
    elif extension == "CAR":
        assert not any(name.startswith("type42_") for name in calls)
    cases += 1

for kind, size, mapper in [(1,8192,1), (41,131072,14), (22,65536,15),
                           (69,32768,34), (78,8192,35), (53,8192,37),
                           (104,8192,38), (105,16384,39), (106,32768,40),
                           (107,65536,41), (108,131072,42), (160,65536,36),
                           (252,16384,252), (253,8192,253)]:
    check(kind, size, mapper)
check(42, 1048576, 43 if enabled else 0)
for kind, size in ((30, 262144), (61, 2097152), (63, 4194304), (75, 1048576), (109, 262144), (110, 524288), (112, 524288)):
    check(kind, size, 43 if enabled else 0)
    check(0x10000000 | kind, size, 0)
    if enabled:
        check(kind, size, 0, image_ok=False)
        check(kind, size, 0, flash_ok=False)
check(0x1000002A, 1048576, 0)
check(62, 2097152, 0)
if enabled:
    check(42, 1048576, 0, image_ok=False)
    check(42, 1048576, 0, flash_ok=False)
if "mpe_load_image" in symbols:
    for image_ok,flash_ok in ((True,True),(False,True),(True,False)):
        check(42,1048576,44 if image_ok and flash_ok else 0,image_ok,flash_ok,"MPE")
        assert state["calls"].count("mpe_load_image")==1
        assert state["calls"].count("type42_verify_fast_flash")==int(image_ok)
        assert "type42_load_image" not in state["calls"]
    # Real menu extension filter accepts MPE only in enabled firmware.
    uc.mem_write(0x20040000,b"SQ1.MPE\0")
    uc.reg_write(UC_ARM_REG_R0,0x20040000)
    uc.reg_write(UC_ARM_REG_LR,0x10000001)
    uc.reg_write(UC_ARM_REG_SP,0x20042000)
    uc.emu_start(symbols["is_valid_file"]|1,0x10000000,count=10000)
    assert uc.reg_read(UC_ARM_REG_R0)==1
if "native_load_image" in symbols:
    for image_ok in (True,False):
        check(0,891784,45 if image_ok else 0,image_ok,False,"MPE",b"A8N1")
        assert state['calls'].count('native_load_image')==1
        assert not any(name in state['calls'] for name in ('mpe_load_image','type42_verify_fast_flash','type42_prepare_bus'))

class PointerRouting:
    """Run the linked caller and prepare body; seed synthetic admitted tables.

    These doubles do not claim to test FatFs, cartridge parsing, checksum bytes,
    or payload integrity. They isolate which already-admitted representation
    the compiled caller publishes after its verifier returns success.
    """
    STOP = 0x30000000
    NAME = 0x20040000
    STACK = 0x20042000

    def __init__(self):
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.u.mem_map(0x10000000, 0x100000)
        self.u.mem_map(0x20000000, 0x42000)
        self.u.mem_map(self.STOP, 0x1000)
        for address, data in segments:
            self.u.mem_write(address, data)
        self.boundaries = {symbols[name] & ~1: name for name in (
            "f_mount", "f_open", "f_close", "f_read", "f_lseek",
            "type42_load_image", "type42_load_standard_image",
            "type42_verify_fast_flash", "a8_package_load_adapter",
            "__wrap_memcpy", "__wrap_memset") if name in symbols}
        self.u.hook_add(UC_HOOK_CODE, self.hook)
        # A failed new admission can leave old tables in RAM. It must not
        # prepare or publish that stale representation as a successful image.
        self.pages = [0x10400000, symbols["cart_ram"], 0x10400400]
        self.bases = [0, 0x10400010]
        self.write_tables()

    def word(self, name, value):
        self.u.mem_write(symbols[name], struct.pack("<I", value))

    def write_tables(self):
        self.u.mem_write(symbols["type42_pages"], struct.pack("<%dI" % len(self.pages), *self.pages))
        self.u.mem_write(symbols["type42_bank_base"], struct.pack("<%dI" % len(self.bases), *self.bases))
        self.word("type42_file_pages", len(self.pages))
        self.word("type42_bank_count", len(self.bases))

    def read_tables(self):
        return (list(struct.unpack("<%dI" % len(self.pages), self.u.mem_read(symbols["type42_pages"], len(self.pages) * 4))),
                list(struct.unpack("<%dI" % len(self.bases), self.u.mem_read(symbols["type42_bank_base"], len(self.bases) * 4))))

    def admit(self):
        kind = 42 if self.kind == "A8M1" else self.kind
        count = {42: 2049, 109: 513, 110: 1025, 112: 1025, 30: 513}[kind]
        # The synthetic fragmented map is injective and deliberately prevents
        # 17-sector raw-bank adjacency. No owner file or physical map is needed.
        raw = [0x10400000 + (i if self.mapping == "direct" else (i * 1031) % 4099) * 512
               for i in range(count)]
        head = 239 if self.kind == 42 else 1 if self.kind == "A8M1" else 17
        cached = 224 if kind == 112 else 256
        cache_indices = list(range(head)) + list(range(count - (cached - head), count))
        self.pages = raw.copy()
        for cache_index, file_index in enumerate(cache_indices):
            self.pages[file_index] = symbols["cart_ram"] + cache_index * 512
        self.bases = []
        for bank in range((count - 1) // 16):
            first = bank * 16
            contiguous = all(self.pages[first + i] == self.pages[first] + i * 512 for i in range(17))
            # Native CAR42 may prefer its raw contiguous bank across the cache
            # seam, but fully cached banks retain their SRAM representation.
            base = self.pages[first] + 16 if contiguous else 0
            if kind == 42 and not contiguous and self.mapping == "direct":
                base = raw[first] + 16
            self.bases.append(base)
        assert any(0x10000000 <= p < 0x11000000 for p in self.pages)
        assert any(0x20000000 <= p < 0x20040000 for p in self.pages)
        if self.mapping == "fragmented":
            assert 0 in self.bases
        self.write_tables()
        self.word("type42_mapper_type", kind)
        self.word("type42_initial_bank", 127 if kind == 42 else 0)
        self.word("type42_bank_mask", len(self.bases) - 1)
        self.word("type42_payload_checksum", 0x12345678)
        self.before = (self.pages.copy(), self.bases.copy())
        self.admitted = True

    def returned(self, value=0):
        self.u.reg_write(UC_ARM_REG_R0, value)
        self.u.reg_write(UC_ARM_REG_PC, self.u.reg_read(UC_ARM_REG_LR))

    def hook(self, emu, address, size, user):
        self.steps += 1
        assert self.steps <= 1000000, "Pointer routing instruction limit"
        assert self.STACK - 4096 <= emu.reg_read(UC_ARM_REG_SP) <= self.STACK
        if address == self.STOP:
            self.finished = True
            emu.emu_stop()
            return
        if address == symbols["type42_prepare_bus"] & ~1:
            # Observe entry only: do not replace the actual linked prepare body.
            self.calls.append("type42_prepare_bus")
            assert self.admitted and self.verified
        name = self.boundaries.get(address)
        if name is None:
            return
        self.calls.append(name)
        r0, r1, r2, r3 = [emu.reg_read(r) for r in
                          (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        result = 0
        if name == "f_lseek":
            self.offset = r1
        elif name == "f_read":
            data = self.file[self.offset:self.offset + r2]
            if self.failure == "short-header" and self.kind != "A8M1":
                data = data[:8]
            elif self.failure == "short-checksum" and self.kind == "A8M1" and self.offset == 8:
                data = data[:3]
            if data:
                emu.mem_write(r1, data)
            emu.mem_write(r3, struct.pack("<I", len(data)))
            self.offset += len(data)
        elif name in ("type42_load_image", "type42_load_standard_image", "a8_package_load_adapter"):
            assert "f_open" in self.calls
            if name == "type42_load_standard_image":
                assert r3 == self.kind
            if self.failure != "loader":
                self.admit()
                result = 1
        elif name == "type42_verify_fast_flash":
            assert self.admitted and "type42_prepare_bus" not in self.calls
            assert self.read_tables() == self.before, "Aliases changed before checksum admission"
            result = int(self.failure != "preflight")
            self.verified = bool(result)
        elif name in ("__wrap_memcpy", "__wrap_memset"):
            emu.mem_write(r0, bytes(emu.mem_read(r1, r2)) if name.endswith("memcpy") else bytes([r1 & 255]) * r2)
            result = r0
        self.returned(result)

    def run(self, kind, mapping="fragmented", failure=None):
        self.kind, self.mapping, self.failure = kind, mapping, failure
        self.calls, self.offset, self.steps = [], 0, 0
        self.admitted = self.verified = self.finished = False
        self.before = (self.pages.copy(), self.bases.copy())
        self.file = (b"A8M1" + bytes(4) + struct.pack(">I", 0x12345678) + bytes(4)
                     if kind == "A8M1" else b"CART" + struct.pack(">III", kind, 0x12345678, 0))
        self.u.mem_write(self.NAME, b"SYNTH.MPE\0" if kind == "A8M1" else b"SYNTH.CAR\0")
        self.u.reg_write(UC_ARM_REG_SP, self.STACK - 16)
        self.u.reg_write(UC_ARM_REG_LR, self.STOP | 1)
        self.u.reg_write(UC_ARM_REG_R0, self.NAME)
        self.u.emu_start(symbols["load_file"] | 1, 0, count=1000000)
        assert self.finished, "Compiled load_file did not return"
        value = self.u.reg_read(UC_ARM_REG_R0)
        expected = 0 if failure else 50 if kind == "A8M1" else 43
        assert value == expected, (kind, mapping, failure, value, expected)
        assert self.calls.count("f_close") == 1 and self.calls[-1] == "f_mount"
        prepare = self.calls.count("type42_prepare_bus")
        verify = self.calls.count("type42_verify_fast_flash")
        assert verify == int(failure not in ("short-header", "short-checksum", "loader"))
        assert prepare == int(not failure and kind != 42)
        convert = lambda p: p + 0x03000000 if prepare and 0x10000000 <= p < 0x11000000 else p
        after = self.read_tables()
        assert after == ([convert(p) for p in self.before[0]], [convert(p) for p in self.before[1]])
        self.pages, self.bases = after
        return {"kind": kind, "mapping": mapping, "failure": failure,
                "returnedMapper": value, "preflightCalls": verify, "realPrepareCalls": prepare,
                "publishedFlashAlias": None if failure else "0x10" if kind == 42 else "0x13",
                "filePages": len(self.pages), "banks": len(self.bases), "instructions": self.steps}


linked_pointer_routing = []
if enabled:
    for kind in (42, 109, 110, 112, 30):
        for mapping in ("direct", "fragmented"):
            linked_pointer_routing.append(PointerRouting().run(kind, mapping))
        for failure in ("short-header", "loader", "preflight"):
            linked_pointer_routing.append(PointerRouting().run(kind, failure=failure))
    if "a8_package_load_adapter" in symbols:
        for mapping in ("direct", "fragmented"):
            linked_pointer_routing.append(PointerRouting().run("A8M1", mapping))
        for failure in ("loader", "short-checksum", "preflight"):
            linked_pointer_routing.append(PointerRouting().run("A8M1", failure=failure))
        reused = PointerRouting()
        # Reused menu state must rebuild the new tables; a prior legacy adapter
        # with mapper 42 cannot make native CAR42 inherit its bypass alias.
        for kind in ("A8M1", 42, 109, 42):
            linked_pointer_routing.append(reused.run(kind))

print(json.dumps({"result": "PASS", "type42_enabled": enabled, "compiled_loader_cases": cases,
                  "linked_pointer_routing": {"actualLoadFileExecuted": enabled,
                      "actualPrepareBodyExecuted": bool(linked_pointer_routing),
                      "admissionBoundaryDoublesExplicit": True,
                      "cases": linked_pointer_routing,
                      "physicalTimingValidated": False}}))
