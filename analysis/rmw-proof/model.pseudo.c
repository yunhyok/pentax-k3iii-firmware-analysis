/* Authored analysis, not recovered manufacturer source or installable firmware.
 * Source: A32 block [0x525d8594,0x525d85d0), hash in source.json.
 * Entry premise: signed32 count > 1; sequential little-endian ordinary RAM.
 */
uint8_t first = (read_byte(pair + 0) | 1u) & ~2u;
uint8_t second = read_byte(pair + 4) & ~3u;
write_byte(pair + 0, first);
write_byte(pair + 4, second);
uint32_t staged0 = read_word(pair + 0);
uint32_t staged1 = read_word(pair + 4);
write_word(pair + 0, (staged0 & 3u) | ((count & 0x3fffffffu) << 2));
write_word(pair + 4, staged1 & 3u);

/* Final words: ((count << 2) modulo2^32) | 1, and0.
 * Initial64 bits can affect intermediate byte writes and actual reads still occur.
 * No physical initial-byte producer or concurrency guarantee is established.
 * The other48 bytes remain outside this proof; existing56-byte RMW allowance stays.
 * Historical31 eventually marks all56 bytes guest-produced, including earlier48.
 */
