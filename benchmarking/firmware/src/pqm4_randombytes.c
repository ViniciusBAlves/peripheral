#include <stddef.h>
#include <stdint.h>

#include <zephyr/random/random.h>

/*
 * Fill pqm4 randomness requests with bytes from Zephyr's CSPRNG.
 */
int PQCLEAN_randombytes(uint8_t *output, size_t output_len)
{
    sys_rand_get(output, output_len);
    return 0;
}
