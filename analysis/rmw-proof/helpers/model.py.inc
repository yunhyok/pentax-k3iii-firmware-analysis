"""Authored bitvector model of the pinned block; no firmware instruction listing."""
def model(old0, old1, count, omit=None):
    first_byte = (old0 & 255) | 1
    if omit != 'clear_first_bit1':
        first_byte = first_byte & ~2
    second_byte = old1 & 255
    if omit != 'clear_second_low2':
        second_byte = second_byte & ~3
    staged0 = (old0 & 0xffffff00) | first_byte
    staged1 = (old1 & 0xffffff00) | second_byte
    final0 = (staged0 & 3) | ((count & 0x3fffffff) << 2)
    final1 = staged1 & 3
    return final0, final1, (first_byte, second_byte, final0, final1)

def prove():
    import z3
    x, y, n = z3.BitVecs('initial_word0 initial_word1 count', 32)
    a, b, stores = model(x, y, n)
    expected = (n << 2) | 1
    solver = z3.Solver()
    solver.add(n > 1, z3.Or(a != expected, b != 0))
    verdict = solver.check()
    if verdict != z3.unsat:
        raise ValueError('manual model proof failed')
    negative = []
    for mutation in ('clear_first_bit1', 'clear_second_low2'):
        a, b, _ = model(x, y, n, omit=mutation)
        s = z3.Solver()
        s.add(n == 0x2e93, z3.Or(a != expected, b != 0))
        status = s.check()
        if status != z3.sat:
            raise ValueError('negative model control failed')
        m = s.model()
        negative.append({'omitted_model_operation': mutation, 'result': str(status),
                         'counterexample': {str(v): hex(m.eval(v, model_completion=True).as_long()) for v in (x, y, n)}})
    samples = []
    for pattern in (0, 0xa5):
        word = int.from_bytes(bytes([pattern]) * 4, 'little')
        substitutions = ((x, z3.BitVecVal(word, 32)), (y, z3.BitVecVal(word, 32)), (n, z3.BitVecVal(0x2e93, 32)))
        samples.append({'initial_pattern': hex(pattern), 'count': '0x2e93',
                        'model_store_values': [hex(z3.simplify(z3.substitute(v, *substitutions)).as_long()) for v in stores]})
    return {'engine': 'Z3', 'version': z3.get_version_string(), 'counterexample_result': str(verdict),
            'universal_variables': 'two arbitrary32-bit initial words and signed32-bit count>1',
            'final_word0': '(count << 2 modulo2^32) | 1', 'final_word1': 0,
            'intermediate_stores_depend_on_initial_bits': True, 'negative_controls': negative,
            'model_examples_not_new_native_observations': samples}
