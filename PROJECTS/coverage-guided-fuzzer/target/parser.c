/* A record container, and the parser for it.
 *
 * The format is a four-byte tag, a count, then that many records. Each record is a
 * one-byte type, a one-byte length, and that many bytes of payload:
 *
 *     "RECS" | count | (type, length, payload) * count
 *
 * A name record carries a callback the parser invokes once the name has been read, and
 * the name and the callback are kept together in one structure -- which is how this
 * kind of code is usually written, because the two belong to each other.
 *
 * The parser checks that a record fits inside the input before reading it, so the
 * reading is bounded. What it does not check is whether the payload fits the name
 * buffer, and a name longer than the buffer runs off the end of it and into the
 * callback that sits immediately after.
 *
 * That is the whole bug, and it is a real one. The bound on the *input* is correct and
 * the bound on the *destination* is missing, which is how this class of defect actually
 * happens; and the consequence is a function pointer under the attacker's control
 * rather than a return address they would first have to find a way to reach, which is
 * the variant that gets exploited in practice.
 *
 * Nothing here is planted to be found by a fuzzer that knows where to look. The tag,
 * the count, the type byte and a length longer than thirty-two all have to be reached
 * in sequence, and coverage is what tells the search it is getting closer.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_BUFFER 32

#ifdef _WIN32
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __attribute__((visibility("default")))
#endif

/* Nothing in the parser calls this. It exists to be reached by hijacking control, and
 * that is how the exploit proves it worked: a run that ends up here is a run whose
 * instruction pointer was taken over rather than merely broken.
 *
 * It writes a marker rather than returning a code, because the process that reaches it
 * is one whose stack has been overwritten, and returning cleanly is not something it
 * can be trusted to do. */
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

EXPORTED void *address_of_win(void) { return (void *)&win; }

typedef void (*callback)(void);

/* The name and what to do with it, together. The buffer comes first and the pointer
 * immediately after it, so a name that is too long is a callback that has been
 * rewritten. */
typedef struct {
    char name[NAME_BUFFER];
    callback on_complete;
} name_record;

static void name_stored(void) { /* the ordinary case does nothing */ }

static void handle_name(const uint8_t *payload, size_t length) {
    name_record record;
    record.on_complete = name_stored;
#ifdef BOUNDED
    /* The fix: the copy respects the destination as well as the input. */
    size_t copied = length < NAME_BUFFER - 1 ? length : NAME_BUFFER - 1;
    memcpy(record.name, payload, copied);
    record.name[copied] = 0;
#else
    /* The bug: `length` was checked against the input, not against this buffer. */
    memcpy(record.name, payload, length);
    record.name[length < NAME_BUFFER ? length : NAME_BUFFER - 1] = 0;
#endif
    /* Called through the pointer that a long name has just overwritten. */
    record.on_complete();
}

static void handle_number(const uint8_t *payload, size_t length) {
    uint32_t value = 0;
    for (size_t i = 0; i < length && i < 4; i++) {
        value = (value << 8) | payload[i];
    }
    (void)value;
}

static int dispatch(const uint8_t *type, const uint8_t *payload, size_t length) {
    switch (*type) {
        case 1: handle_name(payload, length); return 1;
        case 2: handle_number(payload, length); return 1;
        default: return 0;
    }
}

EXPORTED int parse(const uint8_t *input, size_t size) {
    if (size < 5) return 0;
    if (input[0] != 'R') return 0;
    if (input[1] != 'E') return 0;
    if (input[2] != 'C') return 0;
    if (input[3] != 'S') return 0;

    uint8_t count = input[4];
    size_t offset = 5;
    for (uint8_t i = 0; i < count; i++) {
        if (offset + 2 > size) return 0;
        uint8_t type = input[offset];
        uint8_t length = input[offset + 1];
        offset += 2;
        if (offset + length > size) return 0;
        dispatch(&type, input + offset, length);
        offset += length;
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse(data, size);
    return 0;
}
