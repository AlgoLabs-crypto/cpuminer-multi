#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_sha2.h"
#include "sha3/sph_tiger.h"

void x11hash(void *output, const void *input)
{
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_cubehash512_context  ctx_cubehash;
    sph_whirlpool_context    ctx_whirlpool;
    sph_sha512_context       ctx_sha512;
    sph_tiger_context        ctx_tiger;

    // These uint512 in the C++ source of the client are backed by an array of uint32
    uint32_t _ALIGN(64) hashA[16], hashB[16];

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, input, 80);
    sph_jh512_close(&ctx_jh, hashA);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hashA, 64);
    sph_keccak512_close(&ctx_keccak, hashB);

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hashB, 64);
    sph_cubehash512_close(&ctx_cubehash, hashA);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashA, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashB);

    sph_sha512_init(&ctx_sha512);
    sph_sha512(&ctx_sha512, hashB, 64);
    sph_sha512_close(&ctx_sha512, hashA);

    sph_tiger_init(&ctx_tiger);
    sph_tiger(&ctx_tiger, hashA, 64);
    sph_tiger_close(&ctx_tiger, hashB);

    sph_sha512_init(&ctx_sha512);
    sph_sha512(&ctx_sha512, hashB, 64);
    sph_sha512_close(&ctx_sha512, hashA);

    memcpy(output, hashA, 32);
}

int scanhash_x11(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
    uint32_t _ALIGN(128) hash[8];
    uint32_t _ALIGN(128) endiandata[20];
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;

    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t nonce = first_nonce;
    volatile uint8_t *restart = &(work_restart[thr_id].restart);

    if (opt_benchmark)
        ptarget[7] = 0x0cff;

    for (int k = 0; k < 19; k++)
        be32enc(&endiandata[k], pdata[k]);

    do {
        be32enc(&endiandata[19], nonce);
        x11hash(hash, endiandata);

        if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
            work_set_target_ratio(work, hash);
            pdata[19] = nonce;
            *hashes_done = pdata[19] - first_nonce;
            return 1;
        }
        nonce++;

    } while (nonce < max_nonce && !(*restart));

    pdata[19] = nonce;
    *hashes_done = pdata[19] - first_nonce + 1;
    return 0;
}
