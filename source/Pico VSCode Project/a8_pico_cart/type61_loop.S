/* SPDX-License-Identifier: MIT
 * The MegaMax and Flash MegaCart use the same immutable 16 KiB reader.
 * Keep their initial bank and D5 control protocols distinct. */
#define A8_TYPE61_LOOP 1
#define type63_bus_loop type61_bus_loop
#define type63_steady_loop type61_steady_loop
#define type63_steady_loop_end type61_steady_loop_end
#define type63_cached_decode type61_cached_decode
#include "type63_loop.S"
