/*
 * syncd - legacy record synchronization daemon (DEMO / GROUND TRUTH)
 *
 * This is a fictional "legacy" tool written for the Byteguts REA demo.
 * It embeds realistic-looking but FICTIONAL secrets and a non-trivial custom
 * request-signing algorithm. The agent under test never sees this source;
 * it must reconstruct the signer from the stripped binary alone.
 *
 * Secrets are intentionally fake and use no real provider prefixes.
 *
 * Usage:
 *   syncd sign <method> <path> <ts> <body>   -> prints 16-hex-char token
 *   syncd info                               -> prints connection banner
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ---- Embedded configuration (FICTIONAL secrets) ----------------------- */
static const char DB_USER[]  = "syncd_svc";
static const char DB_PASS[]  = "Pr0d-Sync!2019_dbx";
static const char DB_CONN[]  = "postgresql://syncd_svc:Pr0d-Sync!2019_dbx@db-internal.corp.local:5432/records";
static const char API_KEY[]  = "HIT-7f3a9c21b8e4d6f05a1c-REQSIGN";
static const char INT_HOST[] = "sync-gw.internal.corp.local";
static const char SIGN_KEY[] = "r3quest-signing-seed::9b2f.KX";

/* ---- Custom finalizer mixing function -------------------------------- */
static uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

/* A custom non-cryptographic mixing hash (Merkle-Damgard style). */
static uint32_t sig_hash(const unsigned char *data, size_t n, uint32_t seed) {
    uint32_t h = seed ^ 0x9E3779B1u;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint32_t)data[i];
        h  = rotl32(h, 7) * 0x85EBCA77u;
        h ^= rotl32(h, 13);
        h += 0xC2B2AE3Du;
    }
    h ^= h >> 16;
    h *= 0x7FEB352Du;
    h ^= h >> 15;
    return h;
}

/* Build a 256-byte substitution box from the signing key (RC4-style KSA). */
static void build_sbox(unsigned char sbox[256]) {
    size_t klen = strlen(SIGN_KEY);
    for (int i = 0; i < 256; i++) sbox[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + sbox[i] + (unsigned char)SIGN_KEY[i % klen]) & 0xFF;
        unsigned char t = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = t;
    }
}

/* Permute a buffer in place through the sbox, folding position in. */
static void permute(unsigned char *buf, size_t n, const unsigned char sbox[256]) {
    for (size_t i = 0; i < n; i++) {
        unsigned char v = buf[i];
        v = sbox[v];
        v = (unsigned char)(v ^ sbox[(i + 1) & 0xFF]);
        buf[i] = v;
    }
}

/*
 * make_token: two-level keyed construction over the canonical request
 *   (custom, NOT secure).
 *   canonical = METHOD "\n" PATH "\n" TS "\n" BODY
 *   1. substitute canonical bytes through a key-derived sbox (permute)
 *   2. inner = sig_hash(permuted, seed = first 4 bytes of SIGN_KEY LE)
 *   3. outer = sig_hash(SIGN_KEY, seed = inner)
 *   4. token = outer (hi) concatenated with (inner ^ outer) (lo), 16 hex chars
 */
static void make_token(const char *method, const char *path,
                       const char *ts, const char *body, char out[17]) {
    unsigned char buf[4096];
    size_t len = 0;
    len += snprintf((char *)buf + len, sizeof(buf) - len, "%s\n%s\n%s\n%s",
                    method, path, ts, body);
    if (len >= sizeof(buf)) len = sizeof(buf) - 1;

    unsigned char sbox[256];
    build_sbox(sbox);
    permute(buf, len, sbox);

    uint32_t seed = (uint32_t)(unsigned char)SIGN_KEY[0]
                  | ((uint32_t)(unsigned char)SIGN_KEY[1] << 8)
                  | ((uint32_t)(unsigned char)SIGN_KEY[2] << 16)
                  | ((uint32_t)(unsigned char)SIGN_KEY[3] << 24);

    uint32_t inner = sig_hash(buf, len, seed);
    uint32_t outer = sig_hash((const unsigned char *)SIGN_KEY, strlen(SIGN_KEY), inner);
    uint32_t lo = inner ^ outer;

    snprintf(out, 17, "%08x%08x", outer, lo);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "info") == 0) {
        printf("syncd 1.4.2 -> host=%s db=%s\n", INT_HOST, DB_CONN);
        printf("api-key=%s\n", API_KEY);
        return 0;
    }
    if (argc == 6 && strcmp(argv[1], "sign") == 0) {
        char tok[17];
        make_token(argv[2], argv[3], argv[4], argv[5], tok);
        printf("%s\n", tok);
        return 0;
    }
    fprintf(stderr, "usage: %s sign <method> <path> <ts> <body> | info\n", argv[0]);
    return 2;
}
