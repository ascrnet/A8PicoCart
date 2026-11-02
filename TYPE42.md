# Winbond 1, 2 and 4 MiB cartridges

This opt-in contribution updates the earlier Type42 PR with the maintained
native cartridge readers and adds MegaMax 2 MiB support. It targets the original
A8PicoCart PCB with a 16 MiB Winbond RP2040 module. The mapper needs no extra
Atari RAM, wiring, Duo board or accelerator. Individual games may have their
own Atari RAM requirements. Other flash chips are not qualified for this mode.

Build with Pico SDK 2.3.0 and Arm GNU 11.3.Rel1:

```sh
SRC="source/Pico VSCode Project/a8_pico_cart"
cmake -S "$SRC" -B build -G Ninja -DPICO_SDK_PATH=/path/to/pico-sdk \
  -DCMAKE_BUILD_TYPE=Release -DPICO_NO_PICOTOOL=1 -DA8_ENABLE_TYPE42=ON
cmake --build build
python "$SRC/bin_to_uf2.py" build/a8_pico_cart.bin build/a8_pico_cart.uf2
```

`A8_ENABLE_TYPE42=ON` enables all the readers below. The existing option name
is retained; no MPE or Duo flag is needed. OFF retains the SRAM-only upstream
build. The enabled firmware retains upstream's 250 MHz system clock and uses
divider 2 during cartridge service. Menu/USB use their existing settings.

| CAR type | ROM size | Startup and bank control |
| --- | --- | --- |
| 42, old Atarimax | 1 MiB | Bank 127; reads or writes at D500-D57F select by address; D580-D5FF disables RD5. |
| 75, new Atarimax | 1 MiB | Same address-based banking, starting at bank 0. All banks 0-127 remain accessible. |
| 61, MegaMax | 2 MiB | Bank 0; 16 KiB at 8000-BFFF. Reads or writes in D5xx select address bits 0-6; bit 7 disables RD4/RD5. Written data is ignored. |
| 63, Flash MegaCart | 4 MiB | Bank FE; 16 KiB at 8000-BFFF. Writes to D500-D51F latch the data byte; FF disables RD4/RD5. Reads return the bank latch. |

The maintained 256 KiB MegaCart, 256/512 KiB J(atari)Cart and 512 KiB DCart
readers are retained too. Type 64 has a different, data-based 2 MiB protocol
and is not routed to Type61. Flash programming is not implemented.

Formats follow [Atari800's cartridge specification](https://github.com/atari800/atari800/blob/master/DOC/cart.txt).
The parser checks the full big-endian type, exact length and additive checksum,
then maps the original FatFs sectors, including fragmented files and CAR's
16-byte header seam. It does not patch game data or write the filesystem.

The 1 MiB reader retains the newer native head/tail cache and contiguous raw
bank detection. It keeps allocating XIP pointers after its uncached integrity
check. This differs from the older PR's uncached-only native bus path.

The 2/4 MiB paths share immutable half-window maps and the established direct
SSI ROM reader, while keeping their different D5 protocols separate. The arena
stays 128 KiB. Type61 caches its first four banks; Type63 retains its established
first-four/FE policy and optional checked cache hint. Before launch, an SRAM
probe checks every payload byte with SUM/FNV, physical cache seams, SSI mode and
bounded modeled flash latency. Failures return an error to the normal menu.
The steady SRAM loop is installed before launch; no file IO or demand loads
occur while the Atari is reading ROM.

## Testing and hardware status

I have tested the earlier 1 MiB implementation on my Winbond A8PicoCart and
800XL with Ultimate 1MB. I also report working 4 MiB cartridges in the later
maintained firmware. Those reports describe my hardware and those builds;
they do not establish this standalone UF2 on every stock 800XL.

Type61 is newly implemented in this update. My existing Space Quest II CAR is
2,097,168 bytes, type61. The unchanged private image is used locally for parser,
fragmentation, all-bank ARM bus and preflight checks. It is not distributed.
Type61 and Type75 still need physical acceptance of this exact standalone UF2.
Software tests do not measure electrical Atari/RP2040/flash timing or prove a
complete game. The stock 800XL freeze reported against the older PR needs a
retry with the exact new UF2 and an identified Winbond module.

Software checks require `unicorn==2.1.4`, `pyelftools==0.32` and `capstone==5.0.6`.
The real-FatFs 2/4 MiB host fixtures require an actual 32-bit compiler ABI
(`cc -m32` with multilib on Linux), so their pointer table uses the RP2040's
fixed layout. CI builds feature ON/OFF and runs the linked loader, mapper,
fragmentation and preflight tests using synthetic images only.

The public contribution contains generic cartridge code and synthetic tests.
MPE engines, commercial game data, private graphics, the accelerator framework
and Duo's pooled filesystem are separate from this PR.

Remove the cartridge from the Atari before connecting PC USB. Hold BOOTSEL,
connect USB and install the matching UF2 on RPI-RP2. After normal storage
returns, eject and disconnect USB before fitting the cartridge in the Atari.
The firmware remains below the existing filesystem at flash offset 1 MiB.
No eraser or factory image is needed for this application update.
