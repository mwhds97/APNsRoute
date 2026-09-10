/* A stand-in hook API for dynamic-loader regression tests; never patches code. */
void MSHookFunction(void *target, void *replacement, void **original) {
    (void)replacement;
    if (original) *original = target;
}
