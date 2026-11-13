"""Portable CLI boundary tests; --decoded additionally checks relocation and replay equality."""
if not __debug__:
    raise RuntimeError('Assertions required; -O unsupported')
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SIZE = 78683892


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True, help='Existing directory for isolated temporary fixtures')
    parser.add_argument('--output', type=Path, required=True, help='New test result JSON')
    parser.add_argument('--decoded', type=Path, help='Optional exact caller image for positive replay tests')
    args = parser.parse_args()
    if os.path.lexists(args.output):
        raise FileExistsError(args.output)
    if not args.work_dir.is_dir():
        raise NotADirectoryError(args.work_dir)
    results = []
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    with tempfile.TemporaryDirectory(prefix='allocator-tests-', dir=args.work_dir.resolve()) as tmp:
        work = Path(tmp)
        package = work / 'relocated package with spaces'
        package.mkdir()
        (package / 'helpers').mkdir()
        for name in ('replay.py', 'source-ranges.json', 'helpers/native.py.inc', 'helpers/proof.py.inc'):
            shutil.copyfile(HERE / name, package / name)
        cli = package / 'replay.py'
        wrong = work / 'wrong.bin'
        wrong.write_bytes(b'wrong')

        def rejected(name, image, output, message, flags=('-I', '-S')):
            before = digest(output) if output.is_file() else None
            call = subprocess.run([sys.executable, *flags, str(cli), str(image), '--output', str(output)],
                                  cwd=work, env=env, text=True, capture_output=True, timeout=120)
            assert call.returncode != 0 and message in call.stderr, (name, call.stdout, call.stderr)
            if before is not None:
                assert digest(output) == before
            else:
                assert not output.exists()
            results.append({'test': name, 'passed': True, 'returncode': call.returncode,
                            'expected_error': message, 'existing_output_preserved': before is not None})

        rejected('wrong_size', wrong, work / 'a.json', 'decoded input size mismatch')
        for label, size in (('truncated', SIZE - 1), ('oversized', SIZE + 1), ('wrong_hash', SIZE)):
            fixture = work / (label + '.bin')
            with fixture.open('wb') as stream:
                stream.truncate(size)
            rejected(label, fixture, work / (label + '.json'),
                     'decoded input hash mismatch' if size == SIZE else 'decoded input size mismatch')
            fixture.unlink()
        rejected('optimized_before_imports', wrong, work / 'optimized.json', 'Assertions required', ('-O', '-I', '-S'))
        existing = work / 'existing.json'
        existing.write_bytes(b'keep existing output\n')
        rejected('existing_output', wrong, existing, 'output already exists')
        rejected('input_alias', wrong, wrong, 'output aliases')
        rejected('normalized_input_alias', wrong, work / '.' / 'wrong.bin', 'output aliases')
        rejected('helper_output_alias', wrong, package / 'helpers/native.py.inc', 'output aliases')
        hardlink = work / 'hardlink.json'
        os.link(existing, hardlink)
        rejected('hardlink_existing_output', wrong, hardlink, 'output already exists')
        assert digest(existing) == digest(hardlink)
        dangling = work / 'dangling.json'
        try:
            dangling.symlink_to(work / 'absent-target.json')
        except OSError as exc:
            results.append({'test': 'dangling_symlink', 'passed': None, 'status': 'unsupported', 'winerror': getattr(exc, 'winerror', None)})
        else:
            rejected('dangling_symlink', wrong, dangling, 'output already exists')
            assert dangling.is_symlink() and not (work / 'absent-target.json').exists()
        for name in ('native.py.inc', 'proof.py.inc'):
            helper = package / 'helpers' / name
            original = helper.read_bytes()
            sentinel = work / (name + '.executed')
            helper.write_bytes(('from pathlib import Path\nPath(' + repr(str(sentinel)) + ').write_text("executed")\n').encode() + original)
            rejected('tampered_' + name, wrong, work / (name + '.json'), 'helper hash mismatch: ' + name)
            assert not sentinel.exists()
            helper.write_bytes(original)
        if args.decoded:
            image = args.decoded.resolve()
            before = digest(image)
            outputs = []
            for index in range(2):
                output = work / ('positive-' + str(index) + '.json')
                call = subprocess.run([sys.executable, str(cli), str(image), '--output', str(output)],
                                      cwd=work, env=env, text=True, capture_output=True, timeout=120)
                assert call.returncode == 0, (call.stdout, call.stderr)
                outputs.append(output.read_bytes())
            assert outputs[0] == outputs[1] and digest(image) == before
            expected = (HERE / 'verified.json').read_bytes()
            assert outputs[0] == expected
            result = json.loads(outputs[0])
            assert len(result['cases']) == 7
            assert len(result['proof']['cases']) + len(result['proof']['allocated_tails']) == 5
            assert result['cases'][-1]['boundary']['pc'] == '0x525b7a24'
            results.append({'test': 'two_relocated_replays_match_published_projection', 'passed': True,
                            'output_sha256': hashlib.sha256(outputs[0]).hexdigest(),
                            'input_preserved': True, 'cases': 7, 'proof_cases': 5,
                            'canonical_witnesses': result['canonical_witnesses']})
    report = {'schema': 1, 'all_supported_tests_passed': True, 'tests': results,
              'positive_replay_tested': args.decoded is not None,
              'test_script_sha256': digest(Path(__file__)), 'cli_sha256': digest(HERE / 'replay.py')}
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'passed': sum(row['passed'] is True for row in results),
                      'unsupported': sum(row['passed'] is None for row in results)}))


if __name__ == '__main__':
    main()
