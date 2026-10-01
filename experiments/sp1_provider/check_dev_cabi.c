#include "MultiplicationConsistencyProviderRelationReference.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t (*version_fn)(void);
typedef int (*cap_fn)(uint64_t*, size_t*);
typedef int (*prove_fn)(
    const uint64_t*, size_t, const uint64_t*, size_t,
    uint64_t*, size_t*);
typedef int (*verify_fn)(
    const uint64_t*, size_t, const uint64_t*, size_t);

int main(int argc, char** argv) {
    void* handle;
    version_fn version;
    cap_fn capabilities;
    prove_fn prove;
    verify_fn verify;
    uint64_t words[PVIA_MC_CAPABILITY_WORDS];
    uint64_t relation[PVIA_MC_DIGEST_WORDS];
    uint64_t capability[PVIA_MC_DIGEST_WORDS];
    size_t count = 0;

    if (argc != 2) return 2;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }

    version = (version_fn)dlsym(
        handle, PVIA_MC_ABI_VERSION_SYMBOL_NAME);
    capabilities = (cap_fn)dlsym(
        handle, PVIA_MC_ABI_CAPABILITIES_SYMBOL_NAME);
    prove = (prove_fn)dlsym(
        handle, PVIA_MC_ABI_PROVE_SYMBOL_NAME);
    verify = (verify_fn)dlsym(
        handle, PVIA_MC_ABI_VERIFY_SYMBOL_NAME);
    if (!version || !capabilities || !prove || !verify) return 4;
    if (version() != PVIA_MC_ABI_VERSION) return 5;

    if (capabilities(NULL, &count) != 1 ||
        count != PVIA_MC_CAPABILITY_WORDS)
        return 6;
    memset(words, 0, sizeof(words));
    if (capabilities(words, &count) != 1 ||
        count != PVIA_MC_CAPABILITY_WORDS)
        return 7;

    if (words[PVIA_MC_CAP_DOMAIN_INDEX] !=
            PVIA_MC_CAPABILITY_ABI_DOMAIN ||
        words[PVIA_MC_CAP_VERSION_INDEX] != PVIA_MC_ABI_VERSION ||
        words[PVIA_MC_CAP_AVAILABLE_INDEX] != 1 ||
        words[PVIA_MC_CAP_STRONG_SOUNDNESS_INDEX] != 1 ||
        words[PVIA_MC_CAP_ZERO_KNOWLEDGE_INDEX] != 0 ||
        words[PVIA_MC_CAP_BINDS_INPUT_INDEX] != 1 ||
        words[PVIA_MC_CAP_BINDS_OUTPUT_INDEX] != 1 ||
        words[PVIA_MC_CAP_PROTOCOL_ID_INDEX] == 0)
        return 8;

    if (!pvia_mc_reference_relation_binding(relation) ||
        !pvia_mc_reference_digest_equal(
            relation, words + PVIA_MC_CAP_RELATION_BINDING_INDEX))
        return 9;
    if (!pvia_mc_digest_words_nonzero(
            words + PVIA_MC_CAP_IMPLEMENTATION_BINDING_INDEX))
        return 10;

    if (!pvia_mc_reference_capability_binding(
            1, 1, 0, 1, 1,
            words[PVIA_MC_CAP_PROTOCOL_ID_INDEX],
            words + PVIA_MC_CAP_RELATION_BINDING_INDEX,
            words + PVIA_MC_CAP_IMPLEMENTATION_BINDING_INDEX,
            capability))
        return 11;
    if (!pvia_mc_reference_digest_equal(
            capability,
            words + PVIA_MC_CAP_CAPABILITY_BINDING_INDEX))
        return 12;

    puts("SP1_PROVIDER_DEV_C_ABI: PASS");
    dlclose(handle);
    return 0;
}
