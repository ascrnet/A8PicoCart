"""Execute final linked Type63 preparation and immutable SRAM bus loop.

Checks GPIO behavior and explicit timing-model sensitivities. The dedicated
preflight regression owns SUM/FNV/SysTick integrity and latency qualification.
The linked installer executes here; only its standard SDK memcpy call is modeled.
The prepared bytes are checked before activation, which must never recopy them. No physical timing
or complete-game acceptance is claimed. Owner CAR bytes remain unchanged.
"""
from type63_preflight import (cache_slots,cached,hint_bank,SEAM_SLOT,HINT_SLOT,MAX_SEAM_COUNT,TYPE42_FILE_PAGES,HEADER_BYTES,HEADER42_BYTES)
from pathlib import Path
import argparse,hashlib,json,random,struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_MODE_MCLASS
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_PC
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('elf',type=Path)
p.add_argument('--car',type=Path)
p.add_argument('--hint-car',type=Path,help='Append actual whole-bank24 cache-hint preparation and bus controls')
p.add_argument('--reader-baseline-elf',type=Path,help='Require exact552-byte reader identity to a matched-role qualified firmware ELF')
p.add_argument('--allow-stale-counter-relocation',action='store_true',help='Explicitly allow only offset528 type42_stale_reads literal relocation; all other548bytes must match')
p.add_argument('--report',type=Path)
p.add_argument('--deadline-baseline-elf',type=Path,help='Optional earlier linked mapper comparison under identical declared timings')
args=p.parse_args()
sha=lambda data:hashlib.sha256(data).hexdigest()
elf_hash=sha(args.elf.read_bytes());source_hash=sha(Path(__file__).read_bytes())
def linked_reader(path):
    with path.open('rb')as stream:
        elf=ELFFile(stream);sym={s.name:s.entry.st_value for s in elf.get_section_by_name('.symtab').iter_symbols()}
        address=sym['type63_steady_loop']&~1;count=sym['type63_steady_loop_end']-address;assert count==552
        for segment in elf.iter_segments():
            if segment.header.p_type=='PT_LOAD'and segment.header.p_vaddr<=address<address+count<=segment.header.p_vaddr+segment.header.p_filesz:
                at=address-segment.header.p_vaddr;return segment.data()[at:at+count]
        raise AssertionError('Reader missing fromELFloadsegments')
def linked_symbol(path,name):
    with path.open('rb')as stream:
        elf=ELFFile(stream)
        return next(s.entry.st_value for s in elf.get_section_by_name('.symtab').iter_symbols()if s.name==name)

def compare_reader(current,baseline,current_stale,baseline_stale,allow_relocation=False):
    assert len(current)==len(baseline)==552
    if not allow_relocation:
        assert current==baseline,'Hot reader changed fromqualifiedbaseline'
        return dict(byteExact=True,allInstructionsAndOtherLiteralBytesExact=True,relocation=None)
    offset=528
    assert current[offset:offset+4]==struct.pack('<I',current_stale),'Current stale counter literal does not match linked symbol'
    assert baseline[offset:offset+4]==struct.pack('<I',baseline_stale),'Baseline stale counter literal does not match linked symbol'
    assert current[:offset]+current[offset+4:]==baseline[:offset]+baseline[offset+4:],'Reader changed outside named stale counter relocation'
    return dict(byteExact=current==baseline,allInstructionsAndOtherLiteralBytesExact=True,
                relocation=dict(offset=offset,bytes=4,symbol='type42_stale_reads',baselineValue=baseline_stale,currentValue=current_stale,remainingBytesExact=548))

reader_bytes=linked_reader(args.elf)
reader_baseline_hash=None;reader_comparison=None;reader_comparison_negatives=[]
assert not args.allow_stale_counter_relocation or args.reader_baseline_elf,'Explicit relocation requires a baseline ELF'
if args.reader_baseline_elf:
    baseline_bytes=args.reader_baseline_elf.read_bytes();reader_baseline_hash=sha(baseline_bytes)
    old_reader=linked_reader(args.reader_baseline_elf)
    current_stale=linked_symbol(args.elf,'type42_stale_reads');baseline_stale=linked_symbol(args.reader_baseline_elf,'type42_stale_reads')
    reader_comparison=compare_reader(reader_bytes,old_reader,current_stale,baseline_stale,args.allow_stale_counter_relocation)
    if args.allow_stale_counter_relocation:
        for name,offset in(('instruction',0),('named-literal-value',528),('other-literal',536)):
            bad=bytearray(reader_bytes);bad[offset]^=1
            try:compare_reader(bytes(bad),old_reader,current_stale,baseline_stale,True)
            except AssertionError:reader_comparison_negatives.append(name)
            else:raise AssertionError(('Reader comparison mutation accepted',name))
        try:compare_reader(reader_bytes,old_reader,current_stale+4,baseline_stale,True)
        except AssertionError:reader_comparison_negatives.append('wrong-symbol-value')
        else:raise AssertionError('Reader comparison accepted a wrong symbol')
        if reader_bytes!=old_reader:
            try:compare_reader(reader_bytes,old_reader,current_stale,baseline_stale,False)
            except AssertionError:reader_comparison_negatives.append('strict-default-refuses-relocation')
            else:raise AssertionError('Default reader comparison silently allowed relocation')

SERIAL_CLOCKS,SSI_APB_EXTRA,BUSY_TAIL=32,2,2
SSI_RX_UNUSED_BITS=0xdeadbe00
HOLD_SELECTED,SKEW,SOURCE_START,COLD_START=False,0,0,False
PHI,RW,CCTL,S4,S5=(1<<b for b in (22,23,21,24,25))
RD,DATA=3<<26,255<<13
PAYLOAD,PAGES,PERIOD,FALL=4194304,8193,320,220
def fnv1a(data):
    result=2166136261
    for byte in data:result=((result^byte)*16777619)&0xffffffff
    return result

def prepare_copy_hooks(u,symbols):
    """Execute the real installer; model only its narrow SDK memcpy ABI."""
    source=symbols['type63_steady_loop']&~1
    count=symbols['type63_steady_loop_end']-source
    target=symbols['type42_pages']+1024
    assert count==552 and target+count<=symbols['type42_pages']+HINT_SLOT*4
    state=dict(installerEntries=0,copies=[],activation=False,activationWrites=0)
    install=symbols['type63_install_bus']&~1
    service=symbols['__wrap_memcpy']&~1
    u.mem_write(target,b'\xa5'*count)
    def code(emu,address,size,user):
        if address==install:
            assert not state['activation'],'installer called during activation'
            state['installerEntries']+=1
        elif address==service:
            assert not state['activation'],'memcpy called during activation'
            actual=(u.reg_read(UC_ARM_REG_R0),u.reg_read(UC_ARM_REG_R1),u.reg_read(UC_ARM_REG_R2))
            assert actual==(target,source,count),('unexpected SDK memcpy ABI',actual)
            u.mem_write(target,bytes(u.mem_read(source,count)))
            state['copies'].append(dict(target=target,source=source,bytes=count))
            u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
    def write(emu,access,address,size,value,user):
        if state['activation'] and address<target+count and address+size>target:
            state['activationWrites']+=1
            raise AssertionError('activation rewrote preinstalled loop')
    u.hook_add(UC_HOOK_CODE,code,begin=install,end=install)
    u.hook_add(UC_HOOK_CODE,code,begin=service,end=service)
    u.hook_add(UC_HOOK_MEM_WRITE,write)
    return state,source,target,count

def fixture(data,label,mutant=None,single_high=False,extra_bank=0):
    assert len(data)==PAYLOAD+16 and data[:4]==b'CART'
    assert struct.unpack('>I',data[4:8])[0]==63
    assert sum(data[16:])==struct.unpack('>I',data[8:12])[0]
    u = Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
    for address,size in ((0x10000000,0x1000000),(0x13000000,0x1000000),
                         (0x20000000,0x42000),(0x18000000,0x1000),(0xd0000000,0x1000)):
        u.mem_map(address,size)
    with args.elf.open('rb') as stream:
        elf = ELFFile(stream)
        symbols = {s.name:s.entry.st_value for s in elf.get_section_by_name('.symtab').iter_symbols()}
        for segment in elf.iter_segments():
            if segment.header.p_type=='PT_LOAD' and segment.header.p_filesz:
                u.mem_write(segment.header.p_vaddr,segment.data())
    word = lambda address,value:u.mem_write(address,struct.pack('<I',value))
    ram = symbols['cart_ram']
    table_bytes=34816
    assignments,cache_pages=cache_slots(data,extra_bank)
    pages,physical_pages,slot = [],[],0
    for page in range(PAGES):
        if cached(page,extra_bank):
            ptr = ram+table_bytes+assignments[page]*512
            slot += 1
        elif 3200<=page<=3232:
            ptr = 0x10100000+page*512  # complete direct flash bank 100
        else:
            ptr = 0x10400000+((page*1031)%16384)*512
        block = data[page*512:(page+1)*512].ljust(512,b'\xff')
        physical=(0x10100000+page*512) if 3200<=page<=3232 else 0x10400000+((page*1031)%16384)*512
        physical_pages.append(physical)
        u.mem_write(physical,block);u.mem_write(physical+0x03000000,block)
        u.mem_write(ptr,block)
        if ptr>>24==0x10:u.mem_write(ptr+0x03000000,block)
        pages.append(ptr)
    assert slot==len(assignments) and table_bytes+cache_pages*512<=131072
    if not extra_bank:assert cache_pages==slot==162
    u.mem_write(ram,struct.pack('<8193I',*pages))
    u.mem_write(symbols['type42_pages'],bytes(1024))
    seam_pages=(128,8128,8160)+((extra_bank*32,extra_bank*32+32)if extra_bank else())
    u.mem_write(symbols['type42_pages']+HINT_SLOT*4,struct.pack('<6I',extra_bank,*(physical_pages[p]for p in seam_pages),*([0]*(MAX_SEAM_COUNT-len(seam_pages)))))
    for name,value in [('type63_pages',ram),('type42_mapper_type',63),
                       ('type42_payload_checksum',sum(data[16:])),('type63_payload_hash',fnv1a(data[16:])),('type42_initial_bank',254),
                       ('type42_file_pages',PAGES),('type42_bank_count',256)]:word(symbols[name],value)
    def call(name,budget):
        u.reg_write(UC_ARM_REG_SP,0x20041000)
        u.reg_write(UC_ARM_REG_LR,0x10000001)
        u.emu_start(symbols[name]|1,0x10000000,count=budget)
        assert u.reg_read(UC_ARM_REG_PC)==0x10000000,(name,'budget exhausted')
    copy_state,installed_source,installed_target,installed_bytes=prepare_copy_hooks(u,symbols)
    if mutant=='skip-pre-ack-install':
        u.mem_write(symbols['type63_install_bus']&~1,b'\x70\x47') # BX LR
    cache_before=bytes(u.mem_read(ram+table_bytes,cache_pages*512))
    call('type42_prepare_bus',600000)
    assert copy_state['installerEntries']==1 and len(copy_state['copies'])==1,'pre-ACK loop install missing'
    assert bytes(u.mem_read(installed_target,installed_bytes))==bytes(u.mem_read(installed_source,installed_bytes)),'pre-ACK loop bytes differ'
    pages=[ptr+0x03000000 if ptr>>24==0x10 else ptr for ptr in pages]
    biased=tuple((pages[bank*32+half*16+i]-i*512) if bank<4 or bank==254 or bank==extra_bank else ((((physical_pages[bank*32+half*16+i]-i*512)&0xffffff)<<8)|160) for bank in range(256) for half in range(2) for i in range(17))
    bases=tuple((ram+bank*136)|(1 if bank<4 or bank==254 or bank==extra_bank else 0) for bank in range(256))
    assert biased==struct.unpack('<8704I',u.mem_read(ram,34816)),'linked biased-table conversion'
    assert bases==struct.unpack('<256I',u.mem_read(symbols['type42_pages'],1024))
    assert bytes(u.mem_read(ram+table_bytes,cache_pages*512))==cache_before,'cache overwritten by table expansion'
    prepared=bytes(u.mem_read(ram,131072))
    call('type42_prepare_bus',600000)
    assert bytes(u.mem_read(ram,131072))==prepared,'prepare not idempotent'
    assert copy_state['installerEntries']==1 and len(copy_state['copies'])==1,'idempotent prepare reinstalled code'
    # Revised admission/probe is qualified separately by its owning fixture.
    loop_source=symbols['type63_steady_loop']&~1
    loop_bytes=symbols['type63_steady_loop_end']-loop_source
    assert loop_bytes==552,('review copied loop change',loop_bytes)
    if mutant=='remove-final-guards':
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
        ins=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(bytes(u.mem_read(loop_source,loop_bytes)),loop_source))
        patched=0
        for a,b in zip(ins,ins[1:]):
            if a.mnemonic=='tst' and a.op_str=='r1, r6' and b.mnemonic=='bne':
                u.mem_write(b.address,b'\x00\xbf');patched+=1
        assert patched==5,('final guard mutation coverage',patched)
    elif mutant=='remove-refresh-control-guards':
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
        ins=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(bytes(u.mem_read(loop_source,loop_bytes)),loop_source))
        patched=0
        for a,b in zip(ins,ins[1:]):
            if a.mnemonic=='tst' and a.op_str=='r0, r1' and b.mnemonic=='bne':
                u.mem_write(b.address,b'\x00\xbf');patched+=1
        assert patched==2,('refresh control mutation coverage',patched)
    elif mutant=='cold-entry-falls-into-flash':
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
        ins=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(bytes(u.mem_read(loop_source,80)),loop_source))
        patched=0
        for a,b in zip(ins,ins[1:]):
            if a.mnemonic=='isb' and b.mnemonic=='b':
                u.mem_write(b.address,b'\x00\xbf');patched+=1
        assert patched==1,('cold entry mutation coverage',patched)
    elif mutant=='remove-rx-zero-extension':
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
        ins=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(bytes(u.mem_read(loop_source,loop_bytes)),loop_source))
        patched=0
        for a,b in zip(ins,ins[1:]):
            if a.mnemonic=='ldr' and a.op_str=='r0, [r1, #0x60]' and b.mnemonic=='uxtb' and b.op_str=='r0, r0':
                u.mem_write(b.address,b'\x00\xbf');patched+=1
        assert patched==2,('RX zero extension mutation coverage',patched)
    elif mutant=='disabled-returns-to-enabled-decode':
        enabled=bytes(u.mem_read(loop_source+loop_bytes-8,4))
        assert 1025<=struct.unpack('<I',enabled)[0]<1025+loop_bytes
        u.mem_write(loop_source+loop_bytes-4,enabled)
    elif mutant=='latch-low-data':
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
        patched=0
        for i in Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(bytes(u.mem_read(loop_source,loop_bytes)),loop_source):
            if i.mnemonic=='lsrs' and i.op_str.startswith('r0, r3,'):
                instruction=struct.unpack('<H',bytes(u.mem_read(i.address,2)))[0]
                u.mem_write(i.address,struct.pack('<H',instruction&~(7<<3)));patched+=1
        assert patched==1,('last-HIGH mutation coverage',patched)
    if mutant:
        # Fault injection changes the already-installed code as well as source.
        u.mem_write(installed_target,bytes(u.mem_read(loop_source,loop_bytes)))
    cases=[]
    bank=254
    def control(address,value=0,write=True,abort=None,never_high=False):
        nonlocal bank
        previous=bank
        if address<32 and write and not abort and not never_high:bank=value
        cases.append(dict(pins=S4|S5|0x1500|address|(value<<13)|(0 if write else RW),
                          bank=bank,previous=previous,control=True,write=write,value=value,
                          abort=abort,never_high=never_high))
    def read(offset,write=False,unselected=False,fault=None,early=False):
        pins=CCTL|(0 if write else RW)|(S5 if offset<8192 else S4)|(offset&8191)
        if unselected:pins|=S4|S5
        cases.append(dict(pins=pins,bank=bank,previous=bank,control=False,fault=fault,early=early))
    for offset in (0,495,496,511,512,8191,8192,8687,8688,16378,16383):read(offset)
    for value in range(256):
        control(value%32,value)
        control((value*13)%32,write=False)
        for offset in (0,495,496,8191,8192,8687,8688,16383):read(offset)
        read(37,write=True);read(8229,write=True);read(17,unselected=True)
    # Alternate the disabled latch with SRAM, fragmented and direct-flash banks.
    # Repeated FF writes and ignored D5 addresses must not reopen ROM windows;
    # a subsequent valid bank write must restore both windows and readback.
    transitions_begin=len(cases)
    for selected in (0,99,100,254):
        control(31,255);control(0,255)
        for offset in (0,8191,8192,16383):read(offset)
        control(0,write=False);control(31,write=False)
        control(32,selected);control(255,selected)
        read(0);read(8192);control(17,write=False)
        control(17,selected)
        control(0,write=False);control(31,write=False)
        for offset in (0,495,496,8191,8192,8687,8688,16383):read(offset)
    explicit_enable_disable_cases=len(cases)-transitions_begin
    # Every non-register D5 address is ignored, including the MPE mailbox.
    for selected in (3,255):
        control(0,selected)
        for address in range(32,256):
            control(address,address);control(address,write=False)
        for address in range(32):control(address,write=False)
    control(0,3)
    for abort in ('deselect','read','address'):
        for value in (0,254,255):
            control(17,value,abort=abort);read(0);control(0,write=False)
    for value in (0,254,255):control(0,value,never_high=True);read(8192)
    for selected in (0,99,100,254):
        control(0,selected)
        for offset in (0x1555,0x3555):
            for early in (False,True):
                for fault in ('address','select','deselect','write'):
                    read(offset,fault=fault,early=early);read(offset)
    rng=random.Random(63)
    for _ in range(128):control(rng.randrange(32),rng.randrange(256));read(rng.randrange(16384))
    assert len(cases)==4819,'Type63 functional coverage changed'
    single_seen=set()
    index,steps,checked,output,oe=0,0,0,0,0
    started,sram_only,entered=False,False,False
    faults,early_faults,seen=set(),set(),set()
    flash_reads=0
    serial_pending=None;busy_until=0;manual_active=False;ssi_cfg={0:0x5f0300,4:0,8:1,16:1,20:2,76:0,240:0xa0002022,244:1}
    driven_pins=None
    release_pending=None
    successor_releases=0
    successor_release_max_steps=0
    raw_pages={ptr for ptr in pages if ptr>>24==0x13}
    serial_by_bank={}
    loop_source=symbols['type63_steady_loop']&~1
    loop_bytes=symbols['type63_steady_loop_end']-loop_source
    loop_ram=symbols['type42_pages']+1024
    def pins_now():
        c=cases[index];phase=steps%PERIOD
        if phase>=FALL:return CCTL|S4|S5|RW|(0xa6<<13)
        pins=c['pins']
        if c['control'] and c['write'] and phase<170:pins=(pins&~DATA)|(0xd5<<13)
        if c.get('abort') and phase>=130:
            pins|={'deselect':CCTL,'read':RW,'address':32}[c['abort']]
        if index in faults:
            if c['fault']=='address':pins^=1
            elif c['fault']=='select':pins^=S4|S5
            elif c['fault']=='deselect':pins|=S4|S5
            elif c['fault']=='write':pins&=~RW
        if 50<=phase<FALL and not c.get('never_high'):pins|=PHI
        if single_high and c['control'] and c['write'] and not c.get('abort') and not c.get('never_high'):
            if index in single_seen:pins=(pins&~(PHI|DATA))|(0xa6<<13)
            elif phase>=50:pins=(pins&~DATA)|(c['value']<<13)
        return pins
    def expected(pins,c):
        if not pins&RW:return None
        if not pins&CCTL:return c['previous'] if (pins&224)==0 else None
        if pins&(S4|S5)==S4|S5 or c['bank']==255:return None
        offset=(8192 if pins&S4 else 0)+(pins&8191)
        return data[16+c['bank']*16384+offset]
    def code(emu,address,size,user):
        nonlocal index,steps,checked,entered
        if sram_only:assert 0x20000000<=address<0x20042000,('non-SRAM instruction',hex(address))
        if loop_ram<=address<loop_ram+loop_bytes:entered=True
        if entered:assert loop_ram<=address<loop_ram+loop_bytes,'steady loop escaped its copy'
        if not started:return
        steps+=1
        # GPIO may change just after the preceding byte was driven. Once the
        # hold loop observes that successor, relinquish the old byte before
        # decoding another request. Four instructions permit XOR, mask test,
        # untaken hold branch and OE-clear; this is not an electrical deadline.
        if release_pending is not None:
            assert steps-release_pending<=4, ('obsolete bus drive after successor GPIO',index,steps-release_pending)
        if steps%PERIOD==0:
            index+=1
            if index==len(cases):emu.emu_stop();return
        c=cases[index];phase=steps%PERIOD
        if phase==195:
            value=expected(pins_now(),c)
            assert bool(oe&DATA)==(value is not None),(index,'drive availability',c,hex(oe))
            if value is not None:assert output>>13&255==value,(index,'data byte',c)
            assert output&RD==(0 if (c['bank'] if index in single_seen else c['previous'])==255 else RD),'bank enable at observed falling edge'
            checked+=1
        if phase==285:
            assert not oe&DATA,(index,'bus not released')
            assert output&RD==(0 if c['bank']==255 else RD),(index,'bank enable latch',c)
    def mem_read(emu,access,address,size,value,user):
        nonlocal started,flash_reads,release_pending,serial_pending
        if sram_only and 0x13000000<=address<0x14000000:
            assert size==1 and address&~511 in raw_pages,'non-ROM flash access or flash literal'
        if sram_only:assert not 0x10000000<=address<0x11000000,'native bus must use nonallocating XIP'
        if started and 0x13000000<=address<0x14000000:flash_reads+=1
        if started and size==1 and (0x13000000<=address<0x14000000 or ram+table_bytes<=address<ram+131072):
            c=cases[index]
            # Immutable read-only fetches may be abandoned; stale OUTPUT is rejected below.
            if c.get('fault') and not c['early']:faults.add(index)
        if address==0x18000028:
            word(address,6|int(steps<busy_until)|(8 if serial_pending is not None and steps>=serial_pending[0] else 0))
        elif address==0x18000060:
            assert manual_active and serial_pending is not None and steps>=serial_pending[0], 'RX FIFO underrun'
            word(address,serial_pending[1]|SSI_RX_UNUSED_BITS);serial_pending=None
            c=cases[index]
            if c.get('fault') and not c['early']:faults.add(index)
        if address==0xd0000004:
            started=True
            pins=pins_now()
            if oe&DATA and driven_pins is not None and (pins^driven_pins)&0x03a01fff:
                if release_pending is None:release_pending=steps
            if expected(pins,cases[index]) is not None:seen.add(index)
            word(address,pins)
            c=cases[index]
            if single_high and c['control'] and c['write'] and not c.get('abort') and not c.get('never_high') and pins&PHI:single_seen.add(index)
            # Change the request after its initial GPIO sample, before the
            # production prefetch validation. This does not depend on a
            # redundant OE-clear instruction in the new-read path.
            if index in seen and cases[index].get('early') and index not in faults:
                faults.add(index);early_faults.add(index)
    def mem_write(emu,access,address,size,value,user):
        nonlocal output,oe,sram_only,driven_pins,release_pending,successor_releases,successor_release_max_steps,serial_pending,busy_until,manual_active,flash_reads
        if address in (0x18000000,0x18000004,0x18000008,0x18000014):
            offset=address-0x18000000
            if offset in (0,4):assert ssi_cfg[8]==0,'SSI config while enabled'
            ssi_cfg[offset]=value
            manual_active=ssi_cfg[8]==1 and ssi_cfg[0]==0x470300
        elif address==0x18000060:
            assert manual_active and serial_pending is None and steps>=busy_until, 'SSI overlapping command'
            assert value&255==160,'SSI mode byte'
            byte=bytes(u.mem_read(0x13000000+(value>>8),1))[0]
            serial_pending=(steps+12,byte);busy_until=steps+14;flash_reads+=1
            active_bank=cases[index]['bank'];serial_by_bank[active_bank]=serial_by_bank.get(active_bank,0)+1
        if address==0x18000008 and value==0:sram_only=True
        elif address==0xd0000010:output=value
        elif address==0xd0000014:output|=value
        elif address==0xd0000018:output&=~value
        elif address==0xd0000028:
            oe&=~value
            if release_pending is not None:
                successor_releases+=1
                successor_release_max_steps=max(successor_release_max_steps,steps-release_pending)
                release_pending=None
        elif address==0xd0000024:
            oe|=value
            if started and value&DATA:
                byte=expected(pins_now(),cases[index])
                assert byte is not None,(index,'invalid bus drive',cases[index])
                assert output>>13&255==byte,(index,'stale bus byte',cases[index])
                driven_pins=pins_now()
    u.hook_add(UC_HOOK_CODE,code)
    u.hook_add(UC_HOOK_MEM_READ,mem_read)
    u.hook_add(UC_HOOK_MEM_WRITE,mem_write)
    u.reg_write(UC_ARM_REG_SP,0x20041000)
    copy_state['activation']=True
    u.emu_start(symbols['emulate_type42']|1,0,count=len(cases)*PERIOD+20000)
    assert checked==len(cases) and entered,(checked,len(cases))
    assert len(faults)==64 and len(early_faults)==32,(len(faults),len(early_faults))
    assert flash_reads>100
    assert successor_releases>1000 and successor_release_max_steps<=4
    assert biased==struct.unpack('<8704I',u.mem_read(ram,34816))
    assert tuple(bases)==struct.unpack('<256I',u.mem_read(symbols['type42_pages'],1024))
    assert bytes(u.mem_read(loop_ram,loop_bytes))==bytes(u.mem_read(loop_source,loop_bytes))
    if extra_bank:assert serial_by_bank.get(extra_bank,0)==0,'hinted bank fetched via flash'
    return dict(extraCachedBank=extra_bank,uniqueCacheSlots=cache_pages,selectedRawCachePages=len(assignments),seamPages=list(seam_pages),manualCommandsByBank=serial_by_bank,
                singleObservedHighWrites=len(single_seen),label=label,carSha256=sha(data),compiledBusCases=checked,copiedLoopBytes=loop_bytes,
                actualInstallerEntries=copy_state['installerEntries'],modeledSdkMemcpyCalls=copy_state['copies'],activationCodeWrites=copy_state['activationWrites'],
                flashReads=flash_reads,staleReadCases=len(faults),earlyChangedRequestCases=len(early_faults),
                immediateSuccessorReleases=successor_releases,maximumReleaseInstructionsAfterGpio=successor_release_max_steps,
                explicitEnableDisableTransitionCases=explicit_enable_disable_cases)

def deadline_fixture(elf_path,data,fragmented,select_at,selected_bank=248,consecutive=False,upper=False,initial_phase=0,input_delay=2,sample_clock=122,flash_wait=52,transfer=None,write_valid_at=95,extra_bank=0):
    """Execute linked code under declared clocks, not a physical deadline proof.

    Candidate table preparation and the installer are actual linked C. The
    standard SDK memcpy ABI is modeled and all copied bytes are compared.
    Sampling, GPIO settling and SSI/APB clocks remain explicit assumptions.
    No physical pad/board or SSI upper bound is inferred.
    """
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    elf_bytes=elf_path.read_bytes();elf_sha=sha(elf_bytes)
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
    for address,size in ((0x10000000,0x1000000),(0x13000000,0x1000000),(0x20000000,0x42000),
                         (0x18000000,0x1000),(0xd0000000,0x1000)):
        u.mem_map(address,size)
    with elf_path.open('rb') as stream:
        elf=ELFFile(stream)
        symbols={s.name:s.entry.st_value for s in elf.get_section_by_name('.symtab').iter_symbols()}
        for segment in elf.iter_segments():
            if segment.header.p_type=='PT_LOAD' and segment.header.p_filesz:
                u.mem_write(segment.header.p_vaddr,segment.data())
    modern='type63_payload_hash' in symbols
    word=lambda address,value:u.mem_write(address,struct.pack('<I',value))
    ram=symbols['cart_ram'];pages=[];physical_pages=[];slot=0
    assignments,cache_slot_count=cache_slots(data,extra_bank)
    for page in range(PAGES):
        if cached(page,extra_bank) if modern else(page<158 or 8128<=page<=8160):
            pointer=ram+(34816 if modern else 33280)+(assignments[page] if modern else slot)*512;slot+=1
        else:pointer=0x10400000+((page*1031)%16384 if fragmented else page)*512
        block=data[page*512:(page+1)*512].ljust(512,b'\xff')
        physical=0x10400000+((page*1031)%16384 if fragmented else page)*512
        physical_pages.append(physical)
        u.mem_write(physical,block);u.mem_write(physical+0x03000000,block)
        u.mem_write(pointer,block)
        if pointer>>24==0x10:u.mem_write(pointer+0x03000000,block)
        pages.append(pointer)
    assert slot==(len(assignments) if modern else 191)
    assert cache_slot_count<=188
    bases=[pages[bank*32]+16 if all(pages[bank*32+i]==pages[bank*32]+i*512 for i in range(33))
           else 0 for bank in range(256)]
    assert bool(bases[248])==bool(not fragmented)
    u.mem_write(ram,struct.pack('<8193I',*pages))
    u.mem_write(symbols['type42_pages'],bytes(1024) if modern else struct.pack('<256I',*bases))
    seam_pages=(128,8128,8160)+((extra_bank*32,extra_bank*32+32)if extra_bank else())
    u.mem_write(symbols['type42_pages']+HINT_SLOT*4,struct.pack('<6I',extra_bank,*(physical_pages[p]for p in seam_pages),*([0]*(MAX_SEAM_COUNT-len(seam_pages)))))
    word(symbols['type63_pages'],ram)
    word(symbols['type42_mapper_type'],63)
    copy_state,installed_source,installed_target,installed_bytes=prepare_copy_hooks(u,symbols)
    u.reg_write(UC_ARM_REG_SP,0x20041000)
    u.reg_write(UC_ARM_REG_LR,0x10000001)
    # Admission setup only: measured383133legacy/450687hinted instructions.
    # Keep the existing functional-fixture600k bound; bus clock gates are unchanged.
    u.emu_start(symbols['type42_prepare_bus']|1,0x10000000,count=600000)
    assert u.reg_read(UC_ARM_REG_PC)==0x10000000,'linked prepare budget exhausted'
    assert copy_state['installerEntries']==1 and len(copy_state['copies'])==1,'pre-ACK loop install missing'
    assert bytes(u.mem_read(installed_target,installed_bytes))==bytes(u.mem_read(installed_source,installed_bytes)),'pre-ACK loop bytes differ'
    normalize=lambda ptr:ptr+0x03000000 if ptr>>24==0x10 else ptr
    if modern:
        prepared_pages=tuple((pages[bank*32+half*16+i]-i*512) if bank<4 or bank==254 or bank==extra_bank else ((((physical_pages[bank*32+half*16+i]-i*512)&0xffffff)<<8)|160) for bank in range(256) for half in range(2) for i in range(17))
        prepared_bases=tuple((ram+bank*136)|(1 if bank<4 or bank==254 or bank==extra_bank else 0) for bank in range(256))
    else:
        prepared_pages=tuple(map(normalize,pages));prepared_bases=tuple(map(normalize,bases))
    got_pages=struct.unpack('<'+str(len(prepared_pages))+'I',u.mem_read(ram,len(prepared_pages)*4))
    assert prepared_pages==got_pages, [(i,hex(a),hex(b)) for i,(a,b) in enumerate(zip(prepared_pages,got_pages)) if a!=b][:8]
    assert prepared_bases==struct.unpack('<256I',u.mem_read(symbols['type42_pages'],1024))
    before_second=(bytes(u.mem_read(ram,131072)),bytes(u.mem_read(symbols['type42_pages'],2049*4)))
    u.reg_write(UC_ARM_REG_LR,0x10000001)
    u.emu_start(symbols['type42_prepare_bus']|1,0x10000000,count=300000)
    assert before_second==(bytes(u.mem_read(ram,131072)),bytes(u.mem_read(symbols['type42_pages'],2049*4))), 'prepare not idempotent'
    assert copy_state['installerEntries']==1 and len(copy_state['copies'])==1,'idempotent prepare reinstalled code'
    alias=0x13
    # Cover the loader's one-ROM-read-per-four-cycle schedule and consecutive
    # ROM cycles in either 8 KiB half. Every flash load pays independently.
    if transfer:
        schedule=[dict(kind='controlWrite',address=0xd500,value=255)]
        schedule += [dict(kind='ramRead',address=0x700,value=0xd5)]*3
        for repeat in range(32):
            schedule += [dict(event) for event in transfer['cpuCycleSchedule']]
        bank=254
        for event in schedule:
            event['bankBefore']=bank
            if event['kind']=='controlWrite':bank=event['value']
    else:
        schedule=[] if COLD_START else [dict(kind='controlWrite',address=0xd500,value=selected_bank)]+[dict(kind='ramRead',address=0x700,value=0xd5)]*2
        for offset in range((8192 if upper else 0)+SOURCE_START,(8192 if upper else 0)+SOURCE_START+32):
            schedule.append(dict(kind='romRead',address=0x8000+offset,bankBefore=selected_bank))
            if not consecutive:schedule += [dict(kind='ramRead',address=0x700,value=0)]*3
    ssi_pending=None;ssi_commands=0;ssi_busy_until=0;manual_active=False;ssi_config={0:0x5f0300,4:0,8:1,16:1,20:2,76:0,240:0xa0002022,244:1}
    clocks=initial_phase;started=False;previous=None;output=RD;oe=0;sample_index=0;stopped=False
    decoded={};checks=[];failed=[];arrivals={};driven_pins=0;flash_reads=0
    pending_release=None;release_delays=[];ownership_failures=[]
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    def pins():
        observed=max(0,clocks-input_delay);index=observed//140;phase=observed%140
        if index>=len(schedule):return CCTL|RW|S4|S5|0x1200
        event=schedule[index];kind=event['kind'];address=event['address'];clock=PHI if phase>=70 else 0
        if kind=='controlWrite':
            if transfer and phase<select_at:return CCTL|RW|S4|S5|0x726|(0xd5<<13)|clock
            byte=0xd5 if transfer and phase<write_valid_at else event['value']
            return S4|S5|(address&8191)|(byte<<13)|clock
        if kind=='romRead':
            held=HOLD_SELECTED and index>0 and schedule[index-1]['kind']=='romRead'
            if held or phase>=select_at:
                bus_address=address
                if phase<select_at:bus_address=schedule[index-1]['address']
                elif phase<select_at+SKEW:bus_address=address^0x80
                return CCTL|RW|(S5 if address<0xa000 else S4)|(bus_address&8191)|clock
        return CCTL|S4|S5|(0 if kind=='ramWrite' else RW)|(address&8191)|(event.get('value',0)<<13)|clock
    def advance(count):
        nonlocal clocks,sample_index,stopped
        end=clocks+count
        while sample_index<len(schedule) and sample_index*140+sample_clock<=end:
            at=sample_index*140+sample_clock
            if at>=clocks:
                event=schedule[sample_index];kind=event['kind'];offset=event['address']-0x8000
                if kind=='romRead':
                    expected=data[16+event['bankBefore']*16384+offset]
                    correct=bool(oe&DATA) and (output>>13&255)==expected
                    checks.append(correct)
                    if not correct:failed.append(dict(cycle=sample_index,address=event['address']))
                elif oe&DATA:
                    ownership_failures.append(dict(cycle=sample_index,kind=kind,reason='DATA OE active outside ROM read'))
                if transfer:
                    expected_rd=0 if event['bankBefore']==255 else RD
                    if output&RD!=expected_rd:
                        ownership_failures.append(dict(cycle=sample_index,kind=kind,reason='RD state',expected=expected_rd,actual=output&RD))
            sample_index+=1
        clocks=end
        if clocks>(len(schedule)+1)*140:stopped=True;u.emu_stop()
    def code(emu,address,size,user):
        nonlocal previous
        assert not manual_active or not 0x10000000<=address<0x11000000, 'XIP instruction while SSI8 active'
        if started and previous:
            prior,width,mnemonic=previous
            advance(1+int(mnemonic.startswith('b') and address!=prior+width))
        key=(address,size)
        if key not in decoded:
            decoded[key]=next(md.disasm(bytes(u.mem_read(address,size)),address)).mnemonic
        previous=(address,size,decoded[key])
    def mem_read(emu,access,address,size,value,user):
        nonlocal started,pending_release,flash_reads,ssi_pending
        if address==0xd0000004:
            started=True;value=pins();word(address,value)
            if oe&DATA and (value^driven_pins)&0x03a01fff and pending_release is None:
                pending_release=clocks
        elif started and address==0x18000028:
            advance(1+SSI_APB_EXTRA)
            word(address,6|int(clocks<ssi_busy_until)|(8 if ssi_pending is not None and clocks>=ssi_pending[0] else 0))
        elif started and address==0x18000060:
            advance(1+SSI_APB_EXTRA)
            assert ssi_pending is not None and clocks>=ssi_pending[0], 'manual FIFO underrun'
            word(address,ssi_pending[1]|SSI_RX_UNUSED_BITS);ssi_pending=None
        elif started and (0x10000000<=address<0x11000000 or 0x13000000<=address<0x14000000):
            assert not manual_active, 'XIP payload while SSI8 active'
            assert address>>24==alias,'loop did not use linked prepare policy'
            flash_reads+=1
            advance(1+flash_wait)
        elif started and 0x20000000<=address<0x20042000:advance(1)
    def mem_write(emu,access,address,size,value,user):
        nonlocal output,oe,pending_release,driven_pins,ssi_pending,ssi_commands,flash_reads,ssi_busy_until,manual_active
        if address in (0x18000000,0x18000004,0x18000008,0x18000014):
            offset=address-0x18000000
            if offset in (0,4):assert ssi_config[8]==0,'SSI config while enabled'
            ssi_config[offset]=value
            manual_active=ssi_config[8]==1 and ssi_config[0]==0x470300
        elif started and address==0x18000060:
            assert manual_active,'manual command without configured SSI8'
            advance(1+SSI_APB_EXTRA)
            assert ssi_pending is None and value&255==160, 'manual overlapping/bad command'
            assert clocks>=ssi_busy_until, 'manual command before BUSY tail completed'
            pointer=0x13000000+(value>>8)
            byte=bytes(u.mem_read(pointer,1))[0]
            ssi_pending=(clocks+SERIAL_CLOCKS,byte);ssi_busy_until=clocks+SERIAL_CLOCKS+BUSY_TAIL;ssi_commands+=1;flash_reads+=1
        elif address==0xd0000010:output=value
        elif address==0xd0000014:output|=value
        elif address==0xd0000018:output&=~value
        elif address==0xd0000024:
            oe|=value
            if value&DATA:
                driven_pins=pins();arrivals.setdefault(clocks//140,clocks%140)
        elif address==0xd0000028:
            oe&=~value
            if pending_release is not None:
                release_delays.append(clocks-pending_release);pending_release=None
        elif started and 0x20000000<=address<0x20042000:advance(1)
    u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ,mem_read);u.hook_add(UC_HOOK_MEM_WRITE,mem_write)
    u.reg_write(UC_ARM_REG_SP,0x20041000);u.reg_write(UC_ARM_REG_R0,ram)
    u.reg_write(UC_ARM_REG_R1,symbols['type42_pages'])
    copy_state['activation']=True
    u.emu_start(symbols['type63_bus_loop']|1,0,count=(len(schedule)+4)*280)
    assert stopped and len(checks)==32,(stopped,len(checks),clocks)
    if transfer:assert 0<=flash_reads<=160,('rapid transfer unbounded flash',flash_reads)
    else:assert 0<=flash_reads<=160,('unbounded flash loads',flash_reads)
    got_pages=struct.unpack('<'+str(len(prepared_pages))+'I',u.mem_read(ram,len(prepared_pages)*4))
    assert prepared_pages==got_pages, [(i,hex(a),hex(b)) for i,(a,b) in enumerate(zip(prepared_pages,got_pages)) if a!=b][:8]
    assert prepared_bases==struct.unpack('<256I',u.mem_read(symbols['type42_pages'],1024))
    assert sha(elf_path.read_bytes())==elf_sha
    return dict(extraCachedBank=extra_bank,uniqueCacheSlots=cache_slot_count,actualNewPrepareExecuted=True,prepareIdempotent=True,actualInstallerEntries=copy_state['installerEntries'],modeledSdkMemcpyCalls=copy_state['copies'],activationCodeWrites=copy_state['activationWrites'],manualModeConfigured=manual_active,manualSerialCommands=ssi_commands,staleReadRejects=struct.unpack('<I',u.mem_read(symbols['type42_stale_reads'],4))[0],nonRomOwnershipFailures=ownership_failures,writeDataValidClock=write_valid_at if transfer else None,initialPhaseClock=initial_phase,inputSynchronizerClocks=input_delay,dataSampleClock=sample_clock,modernBiasedTable=modern,fragmented=fragmented,selectedBank=selected_bank,selectStableAtClock=select_at,
                schedule='rapid source/FF/underlying-RAM transfer' if transfer else ('consecutive ROM cycles' if consecutive else 'one ROM read per four CPU cycles'),
                half='upper' if upper else 'lower',
                preparedFlashAlias=hex(alias<<24),extraClocksEveryFlashAccess=flash_wait,
                cacheReuse=False,flashAccesses=flash_reads,
                correctSamples=sum(checks),samples=32,failedByteOffsets=failed,
                firstReadOutputEnableClock=arrivals.get(3),
                maximumObservedSuccessorReleaseClocks=max(release_delays,default=0))


def rapid_transfers(data):
    """Observed SF2 routine order, without inventing physical setup times.

    STX $D500; LDA ($A0),Y; LDX #$FF; STX $D500; STA ($A2),Y.
    Source03 $81E1 -> $C000 and02 $8000 -> underlying $8000 were
    observed in the unchanged owner CAR. F2 repeats the first shape with an
    uncached bank as an explicit synthetic stress case, not observed SF2.
    """
    result=[]
    for bank,source,target in ((3,0x81e1,0xc000),(2,0x8000,0x8000),(242,0x81e1,0xc000)):
        byte=data[16+bank*16384+source-0x8000]
        schedule=[dict(kind='ramRead',address=0x726,value=0xd5),
            dict(kind='controlWrite',address=0xd500,value=bank)]
        schedule += [dict(kind='ramRead',address=address,value=value) for address,value in
                     ((0x727,0xb1),(0x728,0xa0),(0xa0,source&255),(0xa1,source>>8))]
        schedule.append(dict(kind='romRead',address=source,value=byte))
        schedule += [dict(kind='ramRead',address=address,value=value) for address,value in
                     ((0x729,0xa2),(0x72a,255),(0x72b,0x8e),(0x72c,0),(0x72d,0xd5))]
        schedule.append(dict(kind='controlWrite',address=0xd500,value=255))
        schedule += [dict(kind='ramRead',address=address,value=value) for address,value in
                     ((0x72e,0x91),(0x72f,0xa2),(0xa2,target&255),(0xa3,target>>8))]
        schedule += [dict(kind='ramDummyRead',address=target),dict(kind='ramWrite',address=target,value=byte)]
        result.append(dict(bank=bank,source=source,target=target,sourceByte=byte,cpuCycleSchedule=schedule))
    return result


payload=bytes((i*37^i>>8^i>>14^i>>20)&255 for i in range(PAYLOAD))
synthetic=b'CART'+struct.pack('>III',63,sum(payload),0)+payload
fixtures=[fixture(synthetic,'synthetic')]
car_hash=None;timing_data=synthetic
if args.car:
    owner=args.car.read_bytes();car_hash=sha(owner);timing_data=owner
    fixtures.append(fixture(owner,'unchanged owner image'))
hinted=None;hint_hash=None
if args.hint_car:
    hinted=args.hint_car.read_bytes();hint_hash=sha(hinted);bank=hint_bank(hinted);assert bank==24
    fixtures.append(fixture(hinted,'unchanged hinted owner image',extra_bank=bank))
single=fixture(synthetic,'single observed HIGH then changed LOW DATA',single_high=True)
assert single['singleObservedHighWrites']>256
negative=[]
for mutant in ('remove-final-guards','remove-refresh-control-guards','cold-entry-falls-into-flash','disabled-returns-to-enabled-decode','latch-low-data','remove-rx-zero-extension','skip-pre-ack-install'):
    try:fixture(synthetic,mutant,mutant=mutant,single_high=mutant=='latch-low-data')
    except AssertionError as error:negative.append(dict(mutant=mutant,result='REJECTED',failure=str(error)))
    else:raise AssertionError(('negative control not rejected',mutant))
candidate=[]
for skew in (0,13):
    SKEW=skew
    for sample in (122,127):
        for select in (25,35,45):
            for upper in (False,True):
                for held in (False,True):
                    HOLD_SELECTED=held
                    for phase in range(13):
                        row=deadline_fixture(args.elf,timing_data,True,select,248,held,upper,phase,2,sample,52)
                        row.update(addressSettlingSkewClocks=skew,heldSelectedBetweenRomCycles=held)
                        candidate.append(row)
assert all(r['correctSamples']==32 and not r['nonRomOwnershipFailures'] for r in candidate if r['selectStableAtClock']<=35),'declared non-atomic gate failed'
sram=[];cold=[]
SKEW=13;HOLD_SELECTED=True
for bank in (0,254):
    for upper in (False,True):
        for phase in range(13):
            row=deadline_fixture(args.elf,timing_data,True,35,bank,True,upper,phase,2,122,52)
            sram.append(row)
for upper in (False,True):
    COLD_START=True
    for phase in range(13):
        row=deadline_fixture(args.elf,timing_data,True,35,254,True,upper,phase,2,122,52)
        row['noBankWriteBeforeFirstRomRead']=True;cold.append(row)
COLD_START=False
assert all(r['correctSamples']==32 and r['manualSerialCommands']==0 for r in sram+cold),'cached/cold FE control failed'
seams=[]
for bank,upper,start in ((3,True,8160),(4,False,0),(253,True,8160),(254,False,0),(254,True,8160)):
    SOURCE_START=start
    for phase in (0,12):
        row=deadline_fixture(args.elf,timing_data,True,35,bank,True,upper,phase,2,122,52)
        row['sourceStartWithinHalf']=start;seams.append(row)
SOURCE_START=0
assert all(r['correctSamples']==32 for r in seams),'cache/flash seam control failed'
hinted_deadlines=[]
if hinted is not None:
    SKEW=13;HOLD_SELECTED=True
    for selected,upper,start in((24,False,0),(24,True,0),(23,True,8160),(25,False,0)):
        SOURCE_START=start
        for phase in range(13):
            row=deadline_fixture(args.elf,hinted,True,35,selected,True,upper,phase,2,122,52,extra_bank=24)
            row['sourceStartWithinHalf']=start;hinted_deadlines.append(row)
    SOURCE_START=0
    assert all(r['correctSamples']==32 and not r['nonRomOwnershipFailures']for r in hinted_deadlines),'hinted/adjacent seam deadline control failed'
    assert all(r['manualSerialCommands']==0 for r in hinted_deadlines if r['selectedBank']==24),'hinted bank opcode schedule used flash'
rapid=[];HOLD_SELECTED=False
rapid_inputs=[('synthetic',synthetic)]
if args.car:rapid_inputs.append(('unchanged owner image',owner))
for label,data in rapid_inputs:
    for transfer in rapid_transfers(data):
        for valid in (95,110,120):
            for phase in range(13):
                row=deadline_fixture(args.elf,data,True,25,transfer['bank'],False,False,phase,2,127,52,transfer,valid)
                row.update(label=label,sourceAddress=transfer['source'],targetAddress=transfer['target'])
                rapid.append(row)
assert all(r['correctSamples']==32 and not r['nonRomOwnershipFailures'] for r in rapid),'rapid FF transfer failed'
assert sha(args.elf.read_bytes())==elf_hash and sha(Path(__file__).read_bytes())==source_hash
if args.car:assert sha(args.car.read_bytes())==car_hash
if args.hint_car:assert sha(args.hint_car.read_bytes())==hint_hash
if args.reader_baseline_elf:assert sha(args.reader_baseline_elf.read_bytes())==reader_baseline_hash
if args.deadline_baseline_elf:raise AssertionError('Earlier raw-pointer table ABI is incompatible; use the retained pre-repair witness receipt')
report=dict(result='PASS',carType=63,firmwareElfSha256=elf_hash,testSourceSha256=source_hash,carImageSha256=car_hash,
    fixtures=fixtures,singleHighFixture=single,negativeControls=negative,fixedCartRamBytes=131072,
    sectorMapBytes=34816,immutableCacheBytes=82944,cacheBanks=[0,1,2,3,254],cachedFileSectors=162,
    hintedCarSha256=hint_hash,hintedOpcodeAndSeamControls=hinted_deadlines,cacheHintSlot=HINT_SLOT,
    frozenHeaderSha256=sha(HEADER_BYTES),type42HeaderSha256=sha(HEADER42_BYTES),
    seamOriginalSlots=list(range(SEAM_SLOT,TYPE42_FILE_PAGES)),copiedLoopBytes=552,actualLinkedPrepareExecuted=True,
    prepareIdempotenceAndCachePreservation=True,preAckLoopInstallation=True,activationRecopiesCode=False,
    preparationInstructionBudget=600000,readerSha256=sha(reader_bytes),readerBaselineElfSha256=reader_baseline_hash,
    readerByteExactToBaseline=reader_comparison['byteExact']if reader_comparison else None,
    readerComparison=reader_comparison,readerComparisonNegativeControls=reader_comparison_negatives,preflightFixtureSourceSha256=sha(Path(__file__).with_name('type63_preflight.py').read_bytes()),
    sdkMemcpyAbiModeledBeforeActivation=True,preflightTestedSeparately=True,physicalTimingValidated=False,fullGameAcceptance=False,
    rapidDisableTransfers=rapid,rapidTransferConditions=len(rapid),rapidTransferRepetitionsPerCondition=32,
    functionalSsiAssumptions='RFNE12 instructions/BUSYtail2 checks functionality only; independent clock model below.',
    deadlineModel=dict(kind='DECLARED_NON_ATOMIC_CLOCK_SENSITIVITY_ONLY',armClockMHz=250,atariCycleArmClocks=140,
        phi2HighStartClock=70,sampleClocks=[122,127],ssiCommandToRxClocks=32,ssiRegisterAccessClocks=4,ssiBusyTailClocks=2,ssiUnusedRxUpperBits=SSI_RX_UNUSED_BITS,
        inputSynchronizerClocks=2,selectClocks=[25,35,45],addressSettlingSkewClocks=[0,13],initialPhaseClocks=list(range(13)),
        candidate=candidate,sramControls=sram,initialFeWithoutBankWrite=cold,cacheFlashSeamControls=seams,
        requiredGateSelectClocks=[25,35],longerDelaySelect45IsNotQualified=True,physicalTimingQualified=False,
        limits='Declared unmeasured serial/APB/GPIO/sample times and bounded phase sweep. Unused RX upper bits are deliberately poisoned, without asserting physical garbage values. No measured SSI/AHB/pad/board upper bound. Low-address settling and held-select are explicit, unlike the historical atomic model.'))
if args.report:args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
