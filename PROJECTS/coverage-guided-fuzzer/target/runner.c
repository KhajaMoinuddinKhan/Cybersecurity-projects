/* The executable the fuzzer drives.
 *
 * Running the target in a process of its own is not incidental: a crash is a
 * memory-safety defect, and a defect in the same process as the fuzzer takes the
 * fuzzer with it. The target therefore never shares an address space with the search.
 *
 * Two ways to drive it, and the difference is throughput.
 *
 *   runner <region> <input-file>          one process, one input
 *   runner --persistent <region>          one process, many inputs
 *
 * The file form costs a process spawn per execution, which on this platform is around
 * twenty-eight milliseconds -- most of it the spawn, not the target. The persistent
 * form reads length-prefixed inputs from standard input and runs them in a loop, so the
 * spawn is paid once for thousands of executions. It is what libFuzzer calls persistent
 * mode and what every fuzzer needs on a platform without fork.
 *
 * The price of the persistent form is that a crash ends the process, and the loop with
 * it. That is handled by the fuzzer rather than here: the process dies, the fuzzer
 * notices the pipe close, and it starts a new one. The coverage from the crashing run is
 * already in shared memory, because the runtime writes straight there, so nothing about
 * the crash is lost.
 *
 * Coverage travels back through a shared-memory region named by the fuzzer, because two
 * processes cannot share a pointer.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COVERAGE_MAP_SIZE 65536
#define MAX_INPUT (1 << 20)

extern void coverage_attach(uint8_t *region);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>

static HANDLE region = NULL;

static uint8_t *attach(const char *name) {
    /* Create if absent, open if present: the fuzzer creates it once and every
     * subsequent execution opens the same one. */
    region = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                                COVERAGE_MAP_SIZE + 8, name);
    if (!region) return NULL;
    return (uint8_t *)MapViewOfFile(region, FILE_MAP_ALL_ACCESS, 0, 0, 0);
}
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

static int region = -1;

static uint8_t *attach(const char *name) {
    region = shm_open(name, O_RDWR, 0600);
    if (region < 0) return NULL;
    void *view = mmap(NULL, COVERAGE_MAP_SIZE + 8, PROT_READ | PROT_WRITE, MAP_SHARED,
                      region, 0);
    return view == MAP_FAILED ? NULL : (uint8_t *)view;
}
#endif

static int read_exactly(uint8_t *buffer, size_t count) {
    /* A short read means the fuzzer has gone; the loop ends and the process exits. */
    size_t got = 0;
    while (got < count) {
        size_t n = fread(buffer + got, 1, count - got, stdin);
        if (n == 0) return 0;
        got += n;
    }
    return 1;
}

static int persistent(void) {
    /* Turn off buffering on both ends: every reply is a four-byte header and a status
     * byte, and a buffered stream would hold them until the buffer filled, which would
     * deadlock the conversation. */
    setvbuf(stdout, NULL, _IONBF, 0);

#ifdef _WIN32
    /* Binary mode, and this is not optional. A stream on this platform is opened in
     * text mode by default, and a text-mode stream treats 0x1A as end-of-file and
     * rewrites 0x0D. Both are ordinary bytes in fuzzer data -- 0x1A is the low byte of
     * every length from 26 to 31, so the very first input that happened to be
     * twenty-six bytes long was reported as the target dying, because the header the
     * fuzzer wrote was read as end-of-file. Any byte of any input could do the same,
     * and 0x0D anywhere in the body would be silently doubled.
     *
     * This is a defect the tool would have shipped with: the fuzzer would have gone on
     * reporting crashes for inputs whose length fell in one range out of every 256, and
     * the crashes would have been reproducible, which is exactly what makes them hard
     * to disbelieve. */
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    static uint8_t buffer[MAX_INPUT];
    for (;;) {
        uint8_t header[4];
        if (!read_exactly(header, 4)) return 0;
        uint32_t length = (uint32_t)header[0] | ((uint32_t)header[1] << 8)
                        | ((uint32_t)header[2] << 16) | ((uint32_t)header[3] << 24);
        /* The end of the conversation is a length no input can have, not a length of
         * zero. Zero is a real input -- the empty one -- and a fuzzer must be able to
         * run it, because an empty input is a legitimate thing to test and the shortest
         * one the search will try. Treating it as a quit signal made every empty input
         * look like a crash. */
        if (length == 0xFFFFFFFFu) return 0;
        if (length > MAX_INPUT) return 5;
        if (!read_exactly(buffer, length)) return 0;
        LLVMFuzzerTestOneInput(buffer, length);
        /* The status byte is written after the run. A crash means this never happens,
         * which is exactly how the fuzzer learns the run died. */
        uint8_t ok = 0;
        fwrite(&ok, 1, 1, stdout);
    }
}

int main(int argc, char **argv) {
#ifdef _WIN32
    /* Do not let the platform stop to report a crash.
     *
     * A process that faults is held while a report is prepared, and the hold lasts
     * seconds. While it lasts the process is neither running nor gone, so its handles
     * stay open, the pipe does not reach end-of-file, and the fuzzer waits. Every crash
     * this target produced was therefore recorded as a hang: the crash happened
     * immediately and the report of it arrived two seconds later, which is long enough
     * for a timeout to fire first.
     *
     * A fuzz target must not stop to be examined. It has to die promptly, because the
     * fuzzer's whole measurement of it is how quickly it stops answering. */
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
                 | SEM_NOOPENFILEERRORBOX);
#endif
    if (argc < 3) return 2;
    int persistent_mode = 0;
    const char *region_name;
    if (strcmp(argv[1], "--persistent") == 0) {
        persistent_mode = 1;
        region_name = argv[2];
    } else {
        region_name = argv[1];
    }

    uint8_t *shared = attach(region_name);
    if (!shared) return 3;
    coverage_attach(shared);

    if (persistent_mode) return persistent();

    FILE *input = fopen(argv[2], "rb");
    if (!input) return 4;
    static uint8_t buffer[MAX_INPUT];
    size_t size = fread(buffer, 1, sizeof buffer, input);
    fclose(input);

    LLVMFuzzerTestOneInput(buffer, size);
    return 0;
}
