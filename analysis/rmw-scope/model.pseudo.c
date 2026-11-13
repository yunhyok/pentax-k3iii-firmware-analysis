/* Authored analysis model; not recovered manufacturer source or a build target.
 * Evidence: verified.json, source [0x525d8774,0x525d8790), 7 A32 instructions.
 * Premises: signed requested_pages > 2, fixed ordinary RAM word, little-endian,
 * sequential normal completion, no concurrent writer/observer or fault.
 * shortcut: address/register/control flow are premises, not emulated here;
 * extend only after their producers have independently verified evidence.
 */
uint32_t allocated_tail_word(uint32_t old_word, uint32_t requested_pages) {
    uint32_t byte = (old_word & 0xffu) | 3u;  /* STRB 0x525d8780 */
    uint32_t staged = (old_word & 0xffffff00u) | byte;
    uint32_t final = (staged & 3u) | ((requested_pages & 0x3fffffffu) << 2);
    return final;                           /* STR 0x525d878c */
}
/* For all old_word, under those premises: final == (requested_pages << 2) | 3.
 * Frozen31 requested_pages: 0x2f50 - 0x2e94 = 0xbc; final = 0x2f3.
 * Initial 0x00000000: byte store 0x03; initial 0xa5a5a5a5: byte store 0xa7.
 * Both historical word stores equal 0x2f3. Intermediate values differ.
 * Physical initial producer remains unknown; original reads still occur.
 * Only [0x56493260,0x56493264) is proved by this model, not its adjacent word.
 * Other44 classified bytes are outside this proof; original56 allowance stays.
 */
