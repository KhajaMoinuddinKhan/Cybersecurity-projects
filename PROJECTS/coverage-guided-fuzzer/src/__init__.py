"""A coverage-guided fuzzer, and the exploit it finds.

The pieces are separable on purpose, because they answer different questions:

    build       compile the instrumented target
    coverage    the edge map, shared with the target process
    target      run inputs, in a fresh process or a long-lived one
    mutate      turn one input into the next
    corpus      the inputs worth keeping, and the ones worth keeping most
    engine      the loop that decides what a run told us
    crash       what a crash is, and the smallest input that still causes it
    exploit     whether the crash is control
    cli         the three verbs
"""
