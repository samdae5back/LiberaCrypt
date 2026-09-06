#include <LiberaCrypt/LiberaCrypt.h>

#include <stdint.h>
#include <string.h>

int main(void) {
    static const uint8_t message[] = {0u};
    uint8_t digest[LIBERAC_SHA2_256_DIGEST_BYTES];
    LiberaCError error;

    if (LIBERAC_VERSION_MAJOR != 0 ||
        LIBERAC_VERSION_MINOR != 6 ||
        LIBERAC_VERSION_PATCH != 0 ||
        strcmp(LIBERAC_VERSION(), LIBERAC_VERSION_STRING) != 0)
        return 1;

    error = LIBERAC_HASH(
        digest, sizeof(digest),
        message, 0u,
        LIBERAC_ALG_HASH_SHA2_256);

    return error == LIBERAC_SUCCESS ? 0 : 1;
}
