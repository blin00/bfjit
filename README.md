bfjit
=====

A (sloppy) brainf*ck JIT written in C.

## Known Issues ("Features")
 * Only works on x64 systems - in particular, only tested on Windows (cygwin gcc) and Linux
 * Fixed code and tape size: exceeding either will lead to bad things happening
 * EOF on getchar sets cell to 0
 * Generated code is not optimized at all
