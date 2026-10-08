/* A second target, and a different defect.
 *
 * This one exists to answer a fair question about the fuzzer: the parser in `target/` was
 * written for it, so finding a bug in that one says less than it looks like it says. This
 * target is a different format with a different bug class, and the fuzzer is pointed at
 * it knowing nothing about it.
 *
 * The format is a count, then that many intervals. Each interval is a start and an end,
 * each a sixteen-bit little-endian value:
 *
 *     count (2 bytes) | (start, end) * count
 *
 * The defect is an integer overflow in the check that the intervals fit inside the input.
 * The count is read as a sixteen-bit value and multiplied by four to get the size the
 * intervals need, and the multiplication is done in sixteen bits -- so a count of 16384
 * gives a size of zero, the check passes, and the loop then runs over sixteen thousand
 * intervals that the input does not hold.
 *
 * Where it lands is the point. The first version of this target read those intervals and
 * did nothing with them, which turned out not to be a memory-safety defect at all: the
 * harness hands the parser a large buffer, so reading past the *logical* end of the input
 * stays inside the allocation and nothing faults. That is worth stating rather than
 * quietly fixing, because it is the difference between a bug and a bug-shaped thing -- a
 * read that goes past what the input contains is a logic error until it leaves the memory
 * the program actually has.
 *
 * So the intervals are accumulated into a fixed array, and the count that the check
 * trusted is what indexes it. A count larger than the array writes past the end of it,
 * which is the same integer overflow arriving somewhere that matters. The class is
 * different from the missing destination bound in the other target: there the arithmetic
 * was right and the bound was absent, here the bound is present and the arithmetic is
 * done at the wrong width.
 *
 * The index is the loop counter, and that is deliberate rather than incidental. The
 * first version of this used a separate counter that only advanced for intervals that
 * were in order, and returned early when one was not -- which meant the array could only
 * be overrun by sixty-five consecutive well-formed intervals, a thing that does not
 * happen by chance and did not happen here. It was a defect that existed on paper and
 * could not be reached, and the fuzzer was right not to find it. A malformed interval
 * now skips its own slot rather than ending the loop, so the counter that the check
 * trusted is the one that indexes the array, which is the arrangement that actually
 * overruns.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __attribute__((visibility("default")))
#endif

#define MAX_INTERVALS 64

EXPORTED volatile int hijacked = 0;

EXPORTED void win(void) {
    hijacked = 1;
    const char *marker = getenv("CGF_MARKER");
    if (!marker) marker = "hijacked.marker";
    FILE *f = fopen(marker, "wb");
    if (f) {
        fwrite("hijacked\n", 1, 9, f);
        fclose(f);
    }
    exit(0);
}

EXPORTED int cgf_parse(const uint8_t *input, size_t size,
                       uint8_t *out, size_t out_capacity, size_t *out_length) {
    (void)out; (void)out_capacity;
    if (out_length) *out_length = 0;
    if (size < 2) return 0;

    uint16_t count = (uint16_t)(input[0] | (input[1] << 8));

    /* The defect: the arithmetic is done at the width of the count. A count of 16384
     * needs 65536 bytes and the product wraps to zero, so the check passes for an input
     * of any size at all -- and for a count of a thousand and twenty-three it passes for
     * an input of four kilobytes, which is the easier one to reach. */
#ifdef BOUNDED
    size_t needed = (size_t)count * 4;          /* the fix: widen before multiplying */
#else
    uint16_t needed = (uint16_t)(count * 4);    /* the defect: it wraps */
#endif
    if (needed > size - 2) return 0;

    /* The intervals, accumulated where the count indexes them. The check above was the
     * only thing standing between the count and this array, and the check is the defect. */
    uint32_t totals[MAX_INTERVALS];
    uint16_t used = 0;

    for (uint16_t i = 0; i < count; i++) {
        size_t at = 2 + (size_t)i * 4;
        uint16_t start = (uint16_t)(input[at] | (input[at + 1] << 8));
        uint16_t end = (uint16_t)(input[at + 2] | (input[at + 3] << 8));
        if (end < start) continue;              /* a malformed interval skips its own slot */
#ifdef BOUNDED
        if (i >= MAX_INTERVALS) break;          /* the fix: the array has a bound too */
#endif
        /* Indexed by the loop counter, which is the count the check above trusted. */
        totals[i] = (uint32_t)(end - start);
        used = i + 1;
    }

    uint32_t total = 0;
    for (uint16_t i = 0; i < used && i < MAX_INTERVALS; i++) total += totals[i];
    if (out_length) *out_length = total < 4 ? total : 4;
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cgf_parse(data, size, NULL, 0, NULL);
    return 0;
}
