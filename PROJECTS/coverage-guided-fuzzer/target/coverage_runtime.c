/* The coverage runtime, which is the fuzzer's half of the instrumentation.
 *
 * The compiler inserts calls on every edge and on every comparison, and the fuzzer has
 * to answer them, which is what makes the feedback possible. Three decisions matter here.
 *
 * `trace-pc` rather than `trace-pc-guard`. The guard form needs the linker to provide
 * the start and end of an array of guard variables, and the linker on Windows does not
 * generate those symbols, so the guard form does not link here at all. `trace-pc` passes
 * nothing and the edge is identified from the return address, which needs no linker
 * cooperation.
 *
 * `trace-cmp` as well as `trace-pc`, because edges say where the program went and
 * comparisons say what it wanted. A parser that rejects an input at `if (d[0] != 'R')`
 * tells a coverage-only fuzzer that it took the rejection edge -- the same thing it says
 * for every wrong first byte, which is no help at all. The comparison says the byte it
 * wanted was 'R', and that is the difference between searching for four bytes out of
 * four billion and being told them one at a time.
 *
 * The map lives in the shared region and is written directly, rather than living here and
 * being copied out at the end. That matters because of what this tool is for: the
 * interesting executions are the ones that crash, and a process that has just died cannot
 * copy anything. Writing straight into shared memory means the coverage that led to a
 * crash is still there afterwards, which is what makes a crash bucketable by the path
 * that reached it rather than only by its exit code.
 *
 * Nothing is cleared here. The fuzzer clears the region before each execution, because
 * clearing sixty-four kilobytes inside every run would cost more than the run.
 *
 * This file must NOT be compiled with the instrumentation it implements. If it is, every
 * call to a callback is a call to itself -- infinite recursion, a stack overflow, and a
 * program that dies before it reads its first input. The build compiles it separately
 * without the flag, which is a fact rather than a request; the attribute below is a
 * second line of defence for anyone who compiles it by hand.
 */

#include <stddef.h>
#include <stdint.h>

#define COVERAGE_MAP_SIZE 65536
#define MAX_COMPARISONS 512

/* The region, once the runner has mapped it. Until then the runtime writes into these,
 * which is what happens when the target is linked into something that is not the fuzzer
 * -- a unit test, or a plain executable. */
static uint8_t local_map[COVERAGE_MAP_SIZE];
/* The comparison buffer has a local home too, and it has to. The region is only mapped
 * when the fuzzer starts the target; a program that links this runtime and calls the
 * parser itself -- a unit test, a harness, anything that is not the fuzzer -- never maps
 * one, and a pointer that is null until then is a pointer that crashes the first time
 * the parser compares anything. Which is immediately, and inside the parser, which makes
 * it look like the parser is broken rather than the runtime. */
static uint8_t local_cmp[4 + MAX_COMPARISONS * 20];
static uint32_t local_cmp_count = 0;
uint8_t *coverage_map = local_map;
uint64_t *coverage_edges = NULL;
uint32_t *comparison_count = &local_cmp_count;
uint8_t *comparison_data = local_cmp;

void coverage_attach(uint8_t *region) {
    coverage_map = region;
    coverage_edges = (uint64_t *)(region + COVERAGE_MAP_SIZE);
    comparison_count = (uint32_t *)(region + COVERAGE_MAP_SIZE + 8);
    comparison_data = region + COVERAGE_MAP_SIZE + 16;
}

/* Each comparison is recorded as two eight-byte operands and a four-byte width, which is
 * what a caller needs to know which bytes of the input the program was looking at. */
static void record(uint64_t a, uint64_t b, uint32_t width, uint32_t is_constant) {
    uint32_t n = *comparison_count;
    if (n >= MAX_COMPARISONS) return;      /* full: the first ones are the ones on the way in */
    uint8_t *slot = comparison_data + (size_t)n * 20;
    for (int i = 0; i < 8; i++) {
        slot[i] = (uint8_t)(a >> (8 * i));
        slot[8 + i] = (uint8_t)(b >> (8 * i));
    }
    /* The width, then whether the first operand came from the program rather than from
     * the input. A comparison against a constant is the program saying what it wants;
     * a comparison between two values it read is not, and the two are worth telling
     * apart because only the first names an expected value. */
    slot[16] = (uint8_t)(width & 0xFF);
    slot[17] = (uint8_t)((width >> 8) & 0xFF);
    slot[18] = (uint8_t)(is_constant & 0xFF);
    slot[19] = 0;
    *comparison_count = n + 1;
}

#if defined(__clang__)
#define NOT_INSTRUMENTED __attribute__((no_instrument_function))
#elif defined(__GNUC__) && __GNUC__ >= 12
#define NOT_INSTRUMENTED __attribute__((no_instrument_function, no_sanitize_coverage))
#else
#define NOT_INSTRUMENTED __attribute__((no_instrument_function))
#endif

NOT_INSTRUMENTED
void __sanitizer_cov_trace_pc(void) {
    /* The return address is the edge. Shifting drops the instruction-alignment bits,
     * which carry nothing about which edge this is. */
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    size_t slot = (size_t)((pc >> 4) % COVERAGE_MAP_SIZE);
    if (!coverage_map[slot]) {
        coverage_map[slot] = 1;
        if (coverage_edges) {
            (*coverage_edges)++;
        }
    }
}

NOT_INSTRUMENTED void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { record(a, b, 1, 0); }
NOT_INSTRUMENTED void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { record(a, b, 2, 0); }
NOT_INSTRUMENTED void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { record(a, b, 4, 0); }
NOT_INSTRUMENTED void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { record(a, b, 8, 0); }
NOT_INSTRUMENTED void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { record(a, b, 1, 1); }
NOT_INSTRUMENTED void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { record(a, b, 2, 1); }
NOT_INSTRUMENTED void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { record(a, b, 4, 1); }
NOT_INSTRUMENTED void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { record(a, b, 8, 1); }
NOT_INSTRUMENTED void __sanitizer_cov_trace_switch(uint64_t value, void *cases) {
    (void)cases;
    record(value, 0, 8, 1);
}
