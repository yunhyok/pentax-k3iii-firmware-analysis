/* Independent scalar C models of two K-3 Mark III v2.20 routines.
 * Tested call domains and firmware addresses: analysis/recompiled-kernels.html.
 */
#include <stdint.h>

/* count > 0; two arrays of count samples; distinct writable result words. */
void sad_ssd_u16(const void *context, const uint16_t *left,
                 const uint16_t *right, int32_t count,
                 uint32_t *sad, uint32_t *ssd)
{
    (void)context;
    uint32_t absolute = 0;
    uint32_t squared = 0;
    for (int32_t i = 0; i < count; ++i) {
        uint32_t a = left[i], b = right[i];
        uint32_t difference = a >= b ? a - b : b - a;
        absolute += difference;
        squared += difference * difference;
    }
    *sad = absolute;
    *ssd = squared;
}

/* Row-major 3x3 matrices; out is separate and stores signed result bit patterns. */
void matrix3_mul_q13(const void *context, uint16_t out[9],
                     const int16_t left[9], const int16_t right[9])
{
    (void)context;
    for (int row = 0; row < 3; ++row) {
        for (int col = 0; col < 3; ++col) {
            uint32_t sum = 4096;
            for (int k = 0; k < 3; ++k)
                sum += (uint32_t)((int32_t)left[3 * row + k] * right[3 * k + col]);
            out[3 * row + col] = (uint16_t)(sum >> 13);
        }
    }
}
