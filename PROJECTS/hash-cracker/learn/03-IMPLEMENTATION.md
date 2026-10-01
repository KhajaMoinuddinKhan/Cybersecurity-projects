# Implementation

`hashlib.new()` keeps the supported algorithm list explicit while avoiding separate code paths for every digest. Blank wordlist lines are ignored, other text is retained exactly apart from line endings, and malformed UTF-8 fails clearly. A missing match returns `None` and a nonzero CLI status instead of a made-up answer.

The test suite covers a match, a complete miss, streaming input, and invalid target validation.
