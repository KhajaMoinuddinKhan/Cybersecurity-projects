/* A record container, and the parser for it.
 *
 * The format is a four-byte tag, a count, then that many records. Each record is a
 * one-byte type, a one-byte length, and that many bytes of payload:
 *
 *     "RECS" | count | (type, length, payload) * count
 *
 * Three record types. A name record carries a callback the parser invokes once the name
 * has been read, and the name and the callback are kept together in one structure --
 * which is how this kind of code is usually written, because the two belong to each
 * other. A number record reads a value. A detail record writes the structure back out.
 *
 * There are two defects, and they are the pair that makes a real exploit rather than a
 * crash.
 *
 * The first is a missing bound. The parser checks that a record fits inside the input
 * before reading it, so the reading is bounded; it never checks that the payload fits the
 * name buffer, and a name longer than the buffer runs off the end of it and into the
 * callback that sits immediately after. The bound on the *input* is correct and the bound
 * on the *destination* is missing, which is how this class of defect actually happens.
 *
 * The second is a disclosure. The detail record writes the whole structure out, including
 * the callback it has just stored, which is a function's address. That is what makes the
 * first defect usable: address space layout randomisation means the attacker cannot know
 * where to point the corrupted callback, and the disclosure tells them. Either defect
 * alone is a finding; together they are an exploit, and they are the two halves that
 * actually appear together in the wild.
 *
 * Nothing here is planted to be found by a fuzzer that knows where to look. The tag, the
 * count, the type byte, a length longer than thirty-two and a detail record to read the
 * address from all have to be reached, and the comparisons the parser makes are what
 * tell the search it is getting closer.
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
 * is one whose stack has been overwritten, and returning cleanly is not something it can
 * be trusted to do. */
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

EXPORTED void *cgf_address_of_win(void) { return (void *)&win; }

typedef void (*callback)(void);

/* The name and what to do with it, together. The buffer comes first and the pointer
 * immediately after it, so a name that is too long is a callback that has been
 * rewritten. */
typedef struct {
    char name[NAME_BUFFER];
    callback on_complete;
} name_record;

static void name_stored(void) { /* the ordinary case does nothing */ }

EXPORTED void *cgf_address_of_name_stored(void) { return (void *)&name_stored; }

static void handle_name(const uint8_t *payload, size_t length) {
    name_record record;
    record.on_complete = name_stored;
#ifdef BOUNDED
    /* The fix: the copy respects the destination as well as the input. */
    size_t copied = length < NAME_BUFFER - 1 ? length : NAME_BUFFER - 1;
    memcpy(record.name, payload, copied);
    record.name[copied] = 0;
#else
    /* The defect: `length` was checked against the input, not against this buffer. */
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

/* The detail record. It writes the structure back to the caller so the record can be
 * round-tripped, and the structure it writes still holds the callback. */
static void handle_detail(const uint8_t *payload, size_t length,
                          uint8_t *out, size_t *out_length, size_t out_capacity) {
    name_record record;
    record.on_complete = name_stored;
    size_t copied = length < NAME_BUFFER - 1 ? length : NAME_BUFFER - 1;
    memcpy(record.name, payload, copied);
    record.name[copied] = 0;
    if (out && out_length) {
        size_t want = sizeof record;
#ifdef BOUNDED
        /* The fix: the caller gets the name, not the address of a function. */
        want = copied;
        if (want > out_capacity) want = out_capacity;
        memcpy(out, record.name, want);
#else
        if (want > out_capacity) want = out_capacity;
        memcpy(out, &record, want);
#endif
        *out_length = want;
    }
}

EXPORTED int cgf_parse(const uint8_t *input, size_t size,
                   uint8_t *out, size_t out_capacity, size_t *out_length) {
    if (out_length) *out_length = 0;
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
        switch (type) {
            case 1: handle_name(input + offset, length); break;
            case 2: handle_number(input + offset, length); break;
            case 3: handle_detail(input + offset, length, out, out_length,
                                  out_capacity); break;
            default: return 0;
        }
        offset += length;
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cgf_parse(data, size, NULL, 0, NULL);
    return 0;
}
