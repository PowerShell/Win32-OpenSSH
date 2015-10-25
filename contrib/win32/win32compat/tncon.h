/*
 * Author: Microsoft Corp.
 *
 * Copyright (c) 2015 Microsoft Corp.
 * All rights reserved
 *
 * Microsoft openssh win32 port
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* tncon.h
 * 
 * Contains terminal emulation console related key definition
 *
 */ 
#ifndef __TNCON_H
#define __TNCON_H

#include "console.h"

#define UP_ARROW         "\033[A"
#define DOWN_ARROW        "\033[B"
#define RIGHT_ARROW       "\033[C"
#define LEFT_ARROW        "\033[D"

#define APP_UP_ARROW         "\033OA"
#define APP_DOWN_ARROW        "\033OB"
#define APP_RIGHT_ARROW       "\033OC"
#define APP_LEFT_ARROW        "\033OD"

// VT100 Function Key's
#define VT100_PF1_KEY           "\x1b\x4f\x50"
#define VT100_PF2_KEY           "\x1b\x4f\x51"
#define VT100_PF3_KEY           "\x1b\x4f\x52"
#define VT100_PF4_KEY           "\x1b\x4f\x53"
#define VT100_PF5_KEY           "\x1b\x4f\x54"
#define VT100_PF6_KEY           "\x1b\x4f\x55"
#define VT100_PF7_KEY           "\x1b\x4f\x56"
#define VT100_PF8_KEY           "\x1b\x4f\x57"
#define VT100_PF9_KEY           "\x1b\x4f\x58"
#define VT100_PF10_KEY           "\x1b\x4f\x59"

// VT420 Key's
#define PF1_KEY           "\033[11~"
#define PF2_KEY           "\033[12~"
#define PF3_KEY           "\033[13~"
#define PF4_KEY           "\033[14~"
#define PF5_KEY           "\033[15~"
#define PF6_KEY           "\033[17~"
#define PF7_KEY           "\033[18~"
#define PF8_KEY           "\033[19~"
#define PF9_KEY           "\033[20~"
#define PF10_KEY           "\033[21~"
#define PF11_KEY           "\033[23~"
#define PF12_KEY           "\033[24~"

#define SHIFT_PF1_KEY           "\033[11;2~"
#define SHIFT_PF2_KEY           "\033[12;2~"
#define SHIFT_PF3_KEY           "\033[13;2~"
#define SHIFT_PF4_KEY           "\033[14;2~"
#define SHIFT_PF5_KEY           "\033[15;2~"
#define SHIFT_PF6_KEY           "\033[17;2~"
#define SHIFT_PF7_KEY           "\033[18;2~"
#define SHIFT_PF8_KEY           "\033[19;2~"
#define SHIFT_PF9_KEY           "\033[20;2~"
#define SHIFT_PF10_KEY           "\033[21;2~"
#define SHIFT_PF11_KEY           "\033[24;2~"
#define SHIFT_PF12_KEY           "\033[25;2~"

#define ALT_PF1_KEY           "\033[11;3~"
#define ALT_PF2_KEY           "\033[12;3~"
#define ALT_PF3_KEY           "\033[13;3~"
#define ALT_PF4_KEY           "\033[14;3~"
#define ALT_PF5_KEY           "\033[15;3~"
#define ALT_PF6_KEY           "\033[17;3~"
#define ALT_PF7_KEY           "\033[18;3~"
#define ALT_PF8_KEY           "\033[19;3~"
#define ALT_PF9_KEY           "\033[20;3~"
#define ALT_PF10_KEY           "\033[21;3~"
#define ALT_PF11_KEY           "\033[24;3~"
#define ALT_PF12_KEY           "\033[25;3~"

#define CTRL_PF1_KEY           "\033[11;4~"
#define CTRL_PF2_KEY           "\033[12;4~"
#define CTRL_PF3_KEY           "\033[13;4~"
#define CTRL_PF4_KEY           "\033[14;4~"
#define CTRL_PF5_KEY           "\033[15;4~"
#define CTRL_PF6_KEY           "\033[17;4~"
#define CTRL_PF7_KEY           "\033[18;4~"
#define CTRL_PF8_KEY           "\033[19;4~"
#define CTRL_PF9_KEY           "\033[20;4~"
#define CTRL_PF10_KEY           "\033[21;4~"
#define CTRL_PF11_KEY           "\033[24;4~"
#define CTRL_PF12_KEY           "\033[25;4~"

#define SHIFT_CTRL_PF1_KEY           "\033[11;6~"
#define SHIFT_CTRL_PF2_KEY           "\033[12;6~"
#define SHIFT_CTRL_PF3_KEY           "\033[13;6~"
#define SHIFT_CTRL_PF4_KEY           "\033[14;6~"
#define SHIFT_CTRL_PF5_KEY           "\033[15;6~"
#define SHIFT_CTRL_PF6_KEY           "\033[17;6~"
#define SHIFT_CTRL_PF7_KEY           "\033[18;6~"
#define SHIFT_CTRL_PF8_KEY           "\033[19;6~"
#define SHIFT_CTRL_PF9_KEY           "\033[20;6~"
#define SHIFT_CTRL_PF10_KEY           "\033[21;6~"
#define SHIFT_CTRL_PF11_KEY           "\033[24;6~"
#define SHIFT_CTRL_PF12_KEY           "\033[25;6~"

#define SHIFT_ALT_PF1_KEY           "\033[11;5~"
#define SHIFT_ALT_PF2_KEY           "\033[12;5~"
#define SHIFT_ALT_PF3_KEY           "\033[13;5~"
#define SHIFT_ALT_PF4_KEY           "\033[14;5~"
#define SHIFT_ALT_PF5_KEY           "\033[15;5~"
#define SHIFT_ALT_PF6_KEY           "\033[17;5~"
#define SHIFT_ALT_PF7_KEY           "\033[18;5~"
#define SHIFT_ALT_PF8_KEY           "\033[19;5~"
#define SHIFT_ALT_PF9_KEY           "\033[20;5~"
#define SHIFT_ALT_PF10_KEY           "\033[21;5~"
#define SHIFT_ALT_PF11_KEY           "\033[24;5~"
#define SHIFT_ALT_PF12_KEY           "\033[25;5~"

#define ALT_CTRL_PF1_KEY           "\033[11;7~"
#define ALT_CTRL_PF2_KEY           "\033[12;7~"
#define ALT_CTRL_PF3_KEY           "\033[13;7~"
#define ALT_CTRL_PF4_KEY           "\033[14;7~"
#define ALT_CTRL_PF5_KEY           "\033[15;7~"
#define ALT_CTRL_PF6_KEY           "\033[17;7~"
#define ALT_CTRL_PF7_KEY           "\033[18;7~"
#define ALT_CTRL_PF8_KEY           "\033[19;7~"
#define ALT_CTRL_PF9_KEY           "\033[20;7~"
#define ALT_CTRL_PF10_KEY           "\033[21;7~"
#define ALT_CTRL_PF11_KEY           "\033[24;7~"
#define ALT_CTRL_PF12_KEY           "\033[25;7~"

#define SHIFT_ALT_CTRL_PF1_KEY           "\033[11;8~"
#define SHIFT_ALT_CTRL_PF2_KEY           "\033[12;8~"
#define SHIFT_ALT_CTRL_PF3_KEY           "\033[13;8~"
#define SHIFT_ALT_CTRL_PF4_KEY           "\033[14;8~"
#define SHIFT_ALT_CTRL_PF5_KEY           "\033[15;8~"
#define SHIFT_ALT_CTRL_PF6_KEY           "\033[17;8~"
#define SHIFT_ALT_CTRL_PF7_KEY           "\033[18;8~"
#define SHIFT_ALT_CTRL_PF8_KEY           "\033[19;8~"
#define SHIFT_ALT_CTRL_PF9_KEY           "\033[20;8~"
#define SHIFT_ALT_CTRL_PF10_KEY           "\033[21;8~"
#define SHIFT_ALT_CTRL_PF11_KEY           "\033[24;8~"
#define SHIFT_ALT_CTRL_PF12_KEY           "\033[25;8~"

#define FIND_KEY          "\x1b\x5b\x31\x7e"
#define INSERT_KEY        "\x1b\x5b\x32\x7e"
#define REMOVE_KEY        "\x1b\x5b\x33\x7e"
#define SELECT_KEY        "\x1b\x5b\x34\x7e"
#define PREV_KEY          "\x1b\x5b\x35\x7e"
#define NEXT_KEY          "\x1b\x5b\x36\x7e"
#define SHIFT_TAB_KEY     "\x1b\x5b\x5A"
#define ESCAPE_KEY		  "\x1b"


#endif