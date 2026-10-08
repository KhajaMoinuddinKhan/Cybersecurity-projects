/* The coverage runtime, which is the fuzzer's half of the instrumentation.
 *
 * The compiler inserts a call on every edge and the fuzzer has to answer it, which is
 * what makes the feedback possible. Two decisions matter here.
 *
 * `trace-pc` rather than `trace-pc-guard`. The guard form needs the linker to provide
 * the start and end of an array of guard variables, and the linker on Windows does not
 * generate those symbols, so the guard form does not link here at all. `trace-pc`
 * passes nothing and the edge is identified from the return address, which needs no
 * linker cooperation.
 *
 * The map lives in the shared region and is written directly, rather than living here
 * and being copied out at the end. That matters because of what this tool is for: the
 * interesting executions are the ones that crash, and a process that has just died
 * cannot copy anything. Writing straight into shared memory means the coverage that led
 * to a crash is still there afterwards, which is what makes a crash bucketable by the
 * path that reached it rather than only by its exit code.
 *
 * Nothing is cleared here. The fuzzer clears the region before each execution, because
 * clearing sixty-four kilobytes inside every run would cost more than the run.
 */

#include <stddef.h>
#include <stdint.h>

#define COVERAGE_MAP_SIZE 65536

/* The region, once the runner has mapped it. Until then the runtime writes into this
 * map, which is what happens when the target is linked into something that is not the
 * fuzzer -- a unit test, or a plain executable. */
static uint8_t local_map[COVERAGE_MAP_SIZE];
uint8_t *coverage_map = local_map;
uint64_t *coverage_edges = NULL;

void coverage_attach(uint8_t *region) {
    coverage_map = region;
    coverage_edges = (uint64_t *)(region + COVERAGE_MAP_SIZE);
}

/* The callback must not itself be instrumented, and this attribute is the only thing
 * that says so.
 *
 * It is a call inserted on every edge, and it is a function like any other, so a
 * compiler that instruments everything it compiles will instrument it -- and then every
 * call to it is a call to itself. That is infinite recursion, and it ends in a stack
 * overflow: the target died with a segmentation fault before running a single input,
 * on every execution, and reported no coverage at all because it never got far enough
 * to record any.
 *
 * Clang excludes the callback automatically, which is why this went unnoticed: the
 * build on one platform worked and the build on the other could not start. GCC does
 * not, and the attribute is what both accept. */
#if defined(__clang__)
/* Clang reads this one and excludes the callback on its own besides. */
#define NOT_INSTRUMENTED __attribute__((no_instrument_function))
#elif defined(__GNUC__) && __GNUC__ >= 12
/* GCC does not treat the callback specially, and the attribute that governs
 * `-finstrument-functions` is not the one that governs coverage. This is. */
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
