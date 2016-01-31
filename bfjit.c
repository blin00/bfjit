// JIT requires x64 calling convention...
#ifndef __x86_64__
#error "x64 only"
#endif

// ...and there's two of them
#ifdef __CYGWIN__
// first arg in rcx (microsoft whyyyy)
#define ARG_RCX
#endif
// otherwise, first arg in rdi

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

// TODO: allow choice of 0/-1/unchanged on EOF
char getchar_bf() {
    int c = getchar();
    if (c == EOF) return 0;
    else return c;
}

const uintptr_t _gc = (uintptr_t) getchar_bf;
const uintptr_t _pc = (uintptr_t) putchar;

enum {INST_PROLOGUE = -1, INST_EPILOGUE = -2, INST_DEBUG = -3, INST_NOP = -4, INST_ZERO = -5};

// emit an instruction
// pretty ugly
int emit(int instr, void* code, uintptr_t jmp) {
    static int last_instr = INST_NOP;
    static uint8_t add_amt = 0;
    static int32_t shift_amt = 0;
    int len = 0;
    uint8_t* code8 = (uint8_t*) code;
    uint16_t* code16 = (uint16_t*) code;
    uint32_t* code32 = (uint32_t*) code;
    if (instr != last_instr) {
        if ((last_instr == '+' || last_instr == '-') && !(instr == '+' || instr == '-')) {
            if (add_amt == 1) {
                code16[0] = 0x03fe;     // inc byte ptr [rbx]
                len = 2;
            } else if (add_amt == -1) {
                code16[0] = 0x0bfe;     // dec byte ptr [rbx]
                len = 2;
            } else if (add_amt != 0) {
                code16[0] = 0x0380;
                code8[2] = add_amt;     // add byte ptr [rbx], add_amt
                len = 3;
            }
            add_amt = 0;
        } else if ((last_instr == '>' || last_instr == '<') && !(instr == '>' || instr == '<')) {
            if (shift_amt == 1) {
                code16[0] = 0xff48;     // inc rbx
                code8[2] = 0xc3;
                len = 3;
            } else if (shift_amt == -1) {
                code16[0] = 0xff48;     // dec rbx
                code8[2] = 0xcb;
                len = 3;
            } else if (shift_amt != 0) {
                if (shift_amt <= 127 && shift_amt >= -128) {
                    code16[0] = 0x8348;
                    code8[2] = 0xc3;
                    code8[3] = (int8_t) shift_amt;          // add rbx, shift_amt
                    len = 4;
                } else {
                    code16[0] = 0x8148;
                    code8[2] = 0xc3;
                    *(int32_t*) &code8[3] = shift_amt;      // add rbx, shift_amt
                    len = 7;
                }
            }
            shift_amt = 0;
        }
    }
    last_instr = instr;
    code8 += len;
    code16 = (uint16_t*) code8;
    code32 = (uint32_t*) code8;
    if (instr == '+') {
        add_amt++;
    } else if (instr == '-') {
        add_amt--;
    } else if (instr == '>') {
        shift_amt++;
    } else if (instr == '<') {
        shift_amt--;
    } else if (instr == '.') {
        // putchar
#ifdef ARG_RCX
        memcpy(code8, "\x48\x0f\xb6\x0b\x48\xb8", 6);    // movzx rcx, byte ptr [rbx]; mov rax,
#else
        memcpy(code8, "\x48\x0f\xb6\x3b\x48\xb8", 6);    // movzx rdi, byte ptr [rbx]; mov rax,
#endif
        memcpy(&code8[6], &_pc, sizeof(_pc));           // _pc;
        memcpy(&code8[6 + sizeof(_pc)], "\xff\xd0", 2); // call rax
        len += 8 + sizeof(_pc);
    } else if (instr == ',') {
        // getchar
        code16[0] = 0xb848;                             // mov rax,
        memcpy(&code8[2], &_gc, sizeof(_gc));           // _gc;
        memcpy(&code8[2 + sizeof(_gc)], "\xff\xd0", 2); // call rax;
        memcpy(&code8[4 + sizeof(_gc)], "\x88\x03", 2); // mov byte ptr [rbx], al
        len += 6 + sizeof(_gc);
    } else if (instr == '[') {
        code32[0] = 0x0f003b80; // cmp byte ptr [rbx], 0; je
        code8[4] = 0x84;        // je
        *(int32_t*) &code8[5] = -9;
        len += 9;
    } else if (instr == ']') {
        code32[0] = 0x0f003b80; // cmp byte ptr [rbx], 0; jne
        code8[4] = 0x85;        // jne
        int32_t offset = (int32_t) (jmp - ((uintptr_t) code8 + 9));
        *(int32_t*) (code8 + 5) = offset;
        len += 9;
    } else if (instr == INST_PROLOGUE) {
#ifdef ARG_RCX
        code32[0] = 0xcb894853; // push rbx; mov rbx, rcx
#else
        code32[0] = 0xfb894853; // push rbx; mov rbx, rdi
#endif
        // shadow space only needed for windows, but doesn't hurt to always include
        code32[1] = 0x20ec8348; // sub rsp, 32
        len += 8;
    } else if (instr == INST_EPILOGUE) {
        code32[0] = 0x20c48348; // add rsp, 32
        code16[2] = 0xc35b;     // pop rbx; ret
        len += 6;
    } else if (instr == INST_DEBUG) {
        code8[0] = 0xcc;        // int3
        len += 1;
    } else if (instr == INST_ZERO) {
        code16[0] = 0x03c6;
        code8[2] = 0x00;
        len += 3;
    }
    return len;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s file\n", argv[0]);
        return 1;
    }
    FILE* f = fopen(argv[1], "r");
    if (!f) {
        fprintf(stderr, "error: could not open file %s\n", argv[1]);
        return 1;
    }
    int c;
    size_t i, length = 0, maxLength = 1024, depth = 0, maxDepth = 1, line = 1, col = 0;
    char* text = malloc(maxLength * sizeof(char));
    if (!text) {
        fprintf(stderr, "error: read buffer allocation failed\n");
        return 1;
    }
    while ((c = fgetc(f)) != EOF) {
        char ch = (char) c;
        if (ch == '\n') {
            line++;
            col = 0;
        }
        col++;
        if (ch != '+' && ch != '-' && ch != '<' && ch != '>' && ch != '[' && ch != ']' && ch != '.' && ch != ',')
            continue;
        if (ch == '[') {
            depth++;
            if (depth > maxDepth) {
                maxDepth = depth;
            }
        } else if (ch == ']') {
            if (depth == 0) {
                fprintf(stderr, "error: closing bracket with no opening bracket at line %zu col %zu\n", line, col);
                return 1;
            }
            depth--;
        }
        length++;
        if (length > maxLength) {
            maxLength *= 2;
            text = realloc(text, maxLength * sizeof(char));
            if (!text) {
                fprintf(stderr, "error: read buffer allocation failed\n");
                return 1;
            }
        }
        text[length - 1] = ch;
    }
    fclose(f);
    if (depth != 0) {
        fprintf(stderr, "error: opening bracket with no closing bracket (need %zu at end)\n", depth);
        return 1;
    }
    const size_t CODE_SIZE = 14 + length * 16;
    uintptr_t jmp[maxDepth];
    uint8_t* code = (uint8_t*) mmap(NULL, CODE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        fprintf(stderr, "error: mmap failed\n");
        return 1;
    }
    memset(code, 0xcc, CODE_SIZE);
    uint8_t* p = code;
    p += emit(INST_PROLOGUE, p, 0);
    for (i = 0; i < length; i++) {
        char ch = text[i];
        int inst = (unsigned char) ch;
        if (ch == ']') {
            depth--;
        }
        if (i < length - 2 && ch == '[' && text[i + 2] == ']' && (text[i + 1] == '+' || text[i + 1] == '-')) {
            inst = INST_ZERO;
            ch = 0; // don't want loop processing
            i += 2;
        }
        p += emit(inst, p, jmp[depth]);
        if (ch == '[') {
            jmp[depth++] = (uintptr_t) p;
        } else if (ch == ']') {
            int32_t offset = (int32_t) ((uintptr_t) p - jmp[depth]);
            *(int32_t*) (jmp[depth] - 4) = offset;
        }
    }
    p += emit(INST_EPILOGUE, p, 0);
    free(text);
    mprotect(code, CODE_SIZE, PROT_READ | PROT_EXEC);
    // TODO: tape bounds checking/custom sizes
    void* data = calloc(30000, 1);
    if (!data) {
        fprintf(stderr, "error: tape allocation failed\n");
        return 1;
    }
    ((void (*)(void*)) code)(data);
    fflush(stdout);
    munmap(code, CODE_SIZE);
    free(data);
    return 0;
}
// Copyright (c) 2016 Brandon Lin
