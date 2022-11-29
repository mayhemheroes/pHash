#include <fuzzer/FuzzedDataProvider.h>
#include <stdint.h>
#include <stdio.h>

#include <climits>

extern int ph_bitcount(uint32_t n);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider provider(data, size);

    uint32_t n = provider.ConsumeIntegral<uint32_t>();
    ph_bitcount(n);

    return 0;
}