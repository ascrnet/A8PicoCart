"""Execute linked MegaMax preparation, SRAM reader and address-bank protocol.

Synthetic images are public; optional owner CARs are read-only. No electrical
timing or physical 800XL acceptance is inferred from the modeled GPIO/SSI.
"""
from pathlib import Path
import argparse, hashlib, json, random, struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('elf',type=Path); p.add_argument('--car',type=Path)
p.add_argument('--report',type=Path); p.add_argument('--preflight',action='store_true')
a=p.parse_args(); sha=lambda b:hashlib.sha256(b).hexdigest()
payload=bytes((i*73^(i>>9)^(i>>17))&255 for i in range(2097152))
data=a.car.read_bytes() if a.car else b'CART'+struct.pack('>III',61,sum(payload),0)+payload
assert len(data)==2097168 and data[:8]==b'CART\0\0\0='
assert sum(data[16:])==struct.unpack('>I',data[8:12])[0]
u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
for at,n in ((0x10000000,0x1000000),(0x13000000,0x1000000),(0x20000000,0x42000),(0x18000000,4096),(0xd0000000,4096)):
    u.mem_map(at,n)
with a.elf.open('rb')as f:
    e=ELFFile(f); s={v.name:v.entry.st_value for v in e.get_section_by_name('.symtab').iter_symbols()}
    for seg in e.iter_segments():
        if seg.header.p_type=='PT_LOAD' and seg.header.p_filesz:u.mem_write(seg.header.p_vaddr,seg.data())
word=lambda at,v:u.mem_write(at,struct.pack('<I',v))
ram=s['cart_ram']; pages=[]; physical=[]
for page in range(4097):
    raw=0x10400000+((page*1031)%16384)*512
    block=data[page*512:(page+1)*512].ljust(512,b'\xff')
    u.mem_write(raw,block); u.mem_write(raw+0x3000000,block);physical.append(raw)
    ptr=ram+34816+page*512 if page<129 else raw
    u.mem_write(ptr,block);pages.append(ptr)
u.mem_write(ram,struct.pack('<4097I',*pages))
u.mem_write(s['type42_pages'],bytes(2049*4))
word(s['type42_pages']+2044*4,physical[128])
for name,value in (('type63_pages',ram),('type42_mapper_type',61),('type42_file_pages',4097),('type42_bank_count',128),('type42_initial_bank',0),('type42_bank_mask',127)):
    word(s[name],value)
def copy_hook(emu,at,size,user):
    if at==(s['__wrap_memcpy']&~1):
        dst,src,n=[u.reg_read(r)for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
        u.mem_write(dst,bytes(u.mem_read(src,n)));u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
hook=u.hook_add(UC_HOOK_CODE,copy_hook)
def call(name):
    u.reg_write(UC_ARM_REG_SP,0x20041000);u.reg_write(UC_ARM_REG_LR,0x10000001)
    u.emu_start(s[name]|1,0x10000000,count=600000)
    assert u.reg_read(UC_ARM_REG_PC)==0x10000000
call('type42_prepare_bus')
prepared=bytes(u.mem_read(ram,131072));call('type42_prepare_bus')
assert bytes(u.mem_read(ram,131072))==prepared
loop=s['type61_steady_loop']&~1; count=s['type61_steady_loop_end']-loop
assert 0<count<=1024
assert bytes(u.mem_read(s['type42_pages']+1024,count))==bytes(u.mem_read(loop,count))
for bank in range(128):
    base=struct.unpack('<I',u.mem_read(s['type42_pages']+bank*4,4))[0]
    assert base==(ram+bank*136)|(bank<4)
    for half in range(2):
        for page in range(17):
            raw=bank*32+half*16+page
            expected=pages[raw]-page*512 if bank<4 else (((physical[raw]-page*512)&0xffffff)<<8)|160
            assert struct.unpack('<I',u.mem_read(ram+(bank*34+half*17+page)*4,4))[0]==expected
u.hook_del(hook)
DATA=0x1fe000;CCTL=1<<21;PHI=1<<22;RW=1<<23;S4=1<<24;S5=1<<25;RD=0xc000000
cases=[];bank=0;enabled=True
def control(address,write,value=0,low=False):
    global bank,enabled
    if not low:bank=address&127;enabled=not address&128
    cases.append(dict(pins=S4|S5|(0 if write else RW)|(value<<13)|address,
                      control=True,bank=bank,enabled=enabled,low=low))
def read(offset,write=False,unselected=False):
    pins=CCTL|(0 if write else RW)|(S4 if offset&8192 else S5)|(offset&8191)
    if unselected:pins|=S4|S5
    value=data[16+bank*16384+offset] if enabled and not write and not unselected else None
    cases.append(dict(pins=pins,control=False,value=value,bank=bank,enabled=enabled))
read(16383)
for b in range(128):
    for write in (False,True):
        control(b,write,value=b^255)
        for off in (0,1,495,496,511,512,8191,8192,8687,8688,8703,8704,16383):read(off)
        read(512,write=True);read(42,unselected=True)
        control(b|128,write);read(0);read(16383)
        control(b,not write);read(127)
control(7,True);control(99,True,low=True);read(8000)
rng=random.Random(61)
for _ in range(512):control(rng.randrange(256),bool(rng.randrange(2)),rng.randrange(256));read(rng.randrange(16384))
state=dict(index=0,steps=0,started=False,output=RD,oe=0,pending=None,manual=False,checked=0,reads=0,sram=False)
PERIOD=400
def pins():
    c=cases[state['index']];phase=state['steps']%PERIOD
    if phase<40 or phase>=260:return CCTL|S4|S5|RW
    return c['pins']|(PHI if 90<=phase<220 and not c.get('low') else 0)
def code(emu,at,size,user):
    if state['sram']:assert 0x20000000<=at<0x20042000,('flash execution',hex(at))
    if not state['started']:return
    state['steps']+=1;phase=state['steps']%PERIOD
    if phase==0:
        state['index']+=1
        if state['index']==len(cases):emu.emu_stop();return
    c=cases[state['index']]
    if phase==200:
        expected=c.get('value')
        assert bool(state['oe']&DATA)==(expected is not None),(state['index'],'drive',c,state)
        if expected is not None:assert (state['output']>>13)&255==expected,(state['index'],'byte',c,state)
        state['checked']+=1
    if phase==300:
        assert not state['oe']&DATA
        assert state['output']&RD==(RD if c['enabled'] else 0),(state['index'],'RD4/RD5',c,state)
def rd(emu,access,at,size,value,user):
    if at==0xd0000004:state['started']=True;word(at,pins())
    elif at==0x18000028:word(at,6|(8 if state['pending'] is not None else 0))
    elif at==0x18000060:
        assert state['pending'] is not None
        word(at,state['pending']|0xa5000000);state['pending']=None
def wr(emu,access,at,size,value,user):
    if at==0x18000008 and value==0:state['sram']=True
    elif at==0x18000000:state['manual']=value==0x470300
    elif at==0x18000060:
        assert state['manual'] and state['pending'] is None and value&255==160
        state['pending']=u.mem_read(0x13000000+(value>>8),1)[0];state['reads']+=1
    elif at==0xd0000010:state['output']=value
    elif at==0xd0000014:state['output']|=value
    elif at==0xd0000018:state['output']&=~value
    elif at==0xd0000028:state['oe']&=~value
    elif at==0xd0000024:
        state['oe']|=value
        if value&DATA:
            c=cases[state['index']];assert c.get('value') is not None,('unexpected drive',c)
            assert state['output']>>13&255==c['value'],('stale byte',c)
u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ,rd);u.hook_add(UC_HOOK_MEM_WRITE,wr)
word(0x18000028,6);u.reg_write(UC_ARM_REG_SP,0x20041000)
u.emu_start(s['emulate_type42']|1,0,count=len(cases)*PERIOD+10000)
assert state['checked']==len(cases) and state['reads']>100
preflight=[]
if a.preflight:
    import type63_preflight as probe_module
    from type63_preflight import Probe,fnv32
    padded=data[16:]*2
    synthetic=b'CART'+struct.pack('>III',63,sum(padded),0)+padded
    for extra,accept in ((52,True),(53,False)):
        probe=Probe(a.elf,synthetic,extra=extra)
        for name,value in (('type42_mapper_type',61),('type42_file_pages',4097),('type42_payload_checksum',sum(data[16:])),('type63_payload_hash',fnv32(data[16:]))):
            probe.word(probe.symbols[name],value)
        probe.seam_pages=(128,)
        probe.cached_raw_pages=129
        original_payload=probe_module.PAYLOAD
        try:
            probe_module.PAYLOAD=2097152
            result,elapsed=probe.call()
            assert result==accept,(extra,result,probe.get('type63_preflight_result'))
            assert probe.payload_reads==2097152 and probe.seam_reads==512
            probe.check_restored(True)
        finally:probe_module.PAYLOAD=original_payload
        preflight.append(dict(extraCycles=extra,accepted=bool(result)))
report=dict(result='PASS',carType=61,cases=len(cases),all128Banks=True,fragmentedFlash=True,
            loopBytes=count,preflight=preflight,elfSha256=sha(a.elf.read_bytes()),carSha256=sha(data),physicalTimingQualified=False)
if a.report:a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
