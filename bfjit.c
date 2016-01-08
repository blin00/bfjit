// JIT requires x64 calling convention...
#ifndef __x86_64__
#error "x64 only"
#endif

// ...and there's two of them
#ifdef __CYGWIN__
// first arg in rcx (microsoft whyyyy)
#define ARG1 "\x0b"
#else
// rdi
#define ARG1 "\x3b"
#endif

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

const size_t CODE_SIZE = 65536;
const size_t LOOP_NEST = 100;
const uint64_t _gc = (uint64_t) getchar_bf;
const uint64_t _pc = (uint64_t) putchar;

// emit an instruction
// pretty ugly
int emit(int instr, void* code, uint64_t jmp) {
    uint8_t* code8 = (uint8_t*) code;
    uint16_t* code16 = (uint16_t*) code;
    uint32_t* code32 = (uint32_t*) code;
    if (instr == '+') {
        code16[0] = 0x03fe;     // inc byte ptr [rbx]
        return 2;
    } else if (instr == '-') {
        code16[0] = 0x0bfe;     // dec byte ptr [rbx]
        return 2;
    } else if (instr == '>') {
        code16[0] = 0xff48;     // inc rbx
        code8[2] = 0xc3;
        return 3;
    } else if (instr == '<') {
        code16[0] = 0xff48;     // dec rbx
        code8[2] = 0xcb;
        return 3;
    } else if (instr == '.') {
        // putchar
        memcpy(code, "\x48\x0f\xb6" ARG1 "\x48\xb8", 6);    // movzx rcx, [rbx]; mov rax,
        memcpy(&code8[6], &_pc, sizeof(_pc));           // _pc;
        memcpy(&code8[6 + sizeof(_pc)], "\xff\xd0", 2); // call rax
        return 8 + sizeof(_pc);
    } else if (instr == ',') {
        // getchar
        code16[0] = 0xb848;                             // mov rax,
        memcpy(&code8[2], &_gc, sizeof(_gc));           // _gc;
        memcpy(&code8[2 + sizeof(_gc)], "\xff\xd0", 2); // call rax;
        memcpy(&code8[4 + sizeof(_gc)], "\x88\x03", 2); // mov byte ptr [rbx], al
        return 6 + sizeof(_gc);
    } else if (instr == '[') {
        code32[0] = 0x0f003b80; // cmp byte ptr [rbx], 0; je
        code8[4] = 0x84;        // je
        *(int32_t*) (code8 + 5) = -9;
        return 9;
    } else if (instr == ']') {
        code32[0] = 0x0f003b80; // cmp byte ptr [rbx], 0; jne
        code8[4] = 0x85;        // jne
        int32_t offset = (int32_t) (jmp - ((uint64_t) code8 + 9));
        *(int32_t*) (code8 + 5) = offset;
        return 9;
    } else if (instr == -1) {
        // prologue
#ifdef __CYGWIN__
        code32[0] = 0xcb894853; // push rbx; mov rbx, rcx
#else
        code32[0] = 0xfb894853; // push rbx; mov rbx, rdi
#endif
        // shadow space only needed for windows, but doesn't hurt to always include
        code32[1] = 0x20ec8348; // sub rsp, 32
        return 8;
    } else if (instr == -2) {
        // epilogue
        code32[0] = 0x20c48348; // add rsp, 32
        code16[2] = 0xc35b;     // pop rbx; ret
        return 6;
    } else if (instr == -3) {
        // debug instruction
        code8[0] = 0xcc;        // int3
        return 1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s file\n", argv[0]);
        return 1;
    }
    // TODO: make size dynamic
    unsigned char* code = (unsigned char*) mmap(NULL, CODE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(code, 0xcc, CODE_SIZE);
    unsigned char* p = code;
    // TODO: make this dynamically allocated
    uint64_t jmp[LOOP_NEST];
    size_t i = 0;
    p += emit(-1, p, 0);
    FILE* f = fopen(argv[1], "r");
    if (!f) {
        fprintf(stderr, "error: could not open file %s\n", argv[1]);
        return 1;
    }
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (c == ']') {
            if (i == 0) {
                fprintf(stderr, "error: ']' without matching '['\n");
                return 1;
            } else {
                i--;
            }
        }
        p += emit((unsigned char) c, p, jmp[i]);
        if (c == '[') {
            if (i >= LOOP_NEST) {
                fprintf(stderr, "error: too many nested loops\n");
                return 1;
            }
            jmp[i++] = (uint64_t) p;
        } else if (c == ']') {
            int32_t offset = (int32_t) ((uint64_t) p - jmp[i]);
            *(int32_t*) (jmp[i] - 4) = offset;
        }
    }
    fclose(f);
    if (i != 0) {
        fprintf(stderr, "error: '[' without matching ']'\n");
        return 1;
    }
    p += emit(-2, p, 0);
    mprotect(code, CODE_SIZE, PROT_READ | PROT_EXEC);
    // TODO: bounds checking/custom tape sizes
    void* data = calloc(30000, 1);
    ((void (*)(void*)) code)(data);
    fflush(stdout);
    munmap(code, CODE_SIZE);
    free(data);
    return 0;
}
// Copyright (c) 2015 Brandon Lin
