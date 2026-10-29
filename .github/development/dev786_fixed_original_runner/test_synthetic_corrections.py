"""Synthetic control-flow/accounting tests. No real Git/Linux/native credit."""
import ast
import hashlib
from pathlib import Path
import stat
import sys
import textwrap
from types import SimpleNamespace as NS
import unittest


SOURCE = Path(sys.argv.pop(1))
RAW = SOURCE.read_bytes()
TREE = ast.parse(RAW, filename=str(SOURCE))
LINES = RAW.decode().splitlines(keepends=True)
PREP = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == '_original_r_git_checks')


def nested(parent, name):
    matches = [n for n in ast.walk(parent) if isinstance(n, ast.FunctionDef) and n.name == name]
    assert len(matches) == 1, (name, len(matches))
    return matches[0]


def segment(node):
    return textwrap.dedent(''.join(LINES[node.lineno - 1:node.end_lineno]))


def require(condition):
    if not condition:
        raise Refusal('refused')


class Refusal(RuntimeError):
    pass


class Clock:
    def __init__(self):
        self.now = 0
        self.calls = 0

    def monotonic_ns(self):
        self.calls += 1
        assert self.calls < 1000, 'synthetic loop exceeded finite bound'
        self.now += 100_000_000
        return self.now

    def sleep(self, seconds):
        self.now += int(seconds * 1_000_000_000)


GIT = nested(PREP, 'git')
LIFECYCLE = next(n for n in GIT.body if isinstance(n, ast.Try) and n.finalbody)
# Extract the original cleanup clock, deadlines and entire owned-child block.
CLEANUP = LIFECYCLE.finalbody[:3]
assert len(CLEANUP) == 3 and isinstance(CLEANUP[-1], ast.If)
CLEANUP_TEXT = ''.join(segment(n) for n in CLEANUP)
HELPERS = ''.join(segment(nested(GIT, name)) for name in ('observe', 'identity', 'group_empty', 'group_signal'))
WRAPPER = '''def exercise():
    owned = True
    terminal = None
    leader_start = None
    group_closed = False
    reaped_consistently = False
    failure = initial_failure
    clean = False
    pipes = []
'''
WRAPPER += textwrap.indent(HELPERS + CLEANUP_TEXT, '    ')
WRAPPER += '    return failure, clean, owned, group_closed, reaped_consistently\n'


class Controls(unittest.TestCase):
    def cleanup(self, mode, initial_failure=None):
        events = []
        census_error = OSError('synthetic census failure')
        account = NS(metadata_visits=128000 if mode == 'budget' else 0)
        clock = Clock()
        observations = 0

        def waitid(*args):
            nonlocal observations
            observations += 1
            events.append('observe')
            if mode == 'echild' and observations >= 2:
                raise ChildProcessError('synthetic ownership loss')
            return NS(si_pid=123, si_code=2, si_status=9) if 9 in events else None

        def getpgid(pid):
            return 999 if mode == 'identity' and observations >= 2 else pid

        def scandir(path):
            events.append('census')
            raise census_error

        def killpg(pid, number):
            assert 'waitpid' not in events, 'signal after reap attempt'
            events.append(number)

        def waitpid(*args):
            events.append('waitpid')
            return (123, 9) if 9 in events else (0, 0)

        namespace = dict(
            time=clock, account=account, clock=lambda: None,
            _ORIGINAL_WORK_CAP=512*1024*1024, _ORIGINAL_METADATA_VISITS=128000,
            _ORIGINAL_READ_CAP=255*1024*1024,
            os=NS(waitid=waitid, getpgid=getpgid, getsid=lambda pid: pid,
                  scandir=scandir, killpg=killpg, waitpid=waitpid,
                  waitstatus_to_exitcode=lambda status: -9, WIFEXITED=lambda status: False,
                  WEXITSTATUS=lambda status: 0, WIFSIGNALED=lambda status: True,
                  WTERMSIG=lambda status: 9, WCOREDUMP=lambda status: False, P_PID=1, WEXITED=2, WNOHANG=4,
                  WNOWAIT=8, CLD_EXITED=1, CLD_KILLED=2, CLD_DUMPED=3),
            signal=NS(SIGTERM=15, SIGKILL=9), child=NS(pid=123, returncode=None),
            record=NS(wait_status=None, waitid=None), _original_r_require=require,
            initial_failure=initial_failure, drain=lambda: None,
        )
        exec(compile(segment(nested(PREP, 'visit')), str(SOURCE), 'exec'), namespace)
        exec(compile(WRAPPER, str(SOURCE), 'exec'), namespace)
        result = namespace['exercise']()
        return events, result, census_error

    def test_census_error_still_attempts_term_and_kill(self):
        events, (failure, clean, owned, closed, reaped), error = self.cleanup('census')
        self.assertEqual([x for x in events if isinstance(x, int)], [15, 9])
        self.assertIs(failure, error)
        self.assertFalse(clean)
        self.assertTrue(closed and reaped)
        self.assertFalse(owned)

    def test_census_budget_exhaustion_still_attempts_termination(self):
        events, result, _ = self.cleanup('budget')
        self.assertEqual([x for x in events if isinstance(x, int)], [15, 9])
        self.assertIsInstance(result[0], Refusal)
        self.assertFalse(result[1])

    def test_first_failure_survives_cleanup(self):
        first = TimeoutError('synthetic original deadline')
        events, result, _ = self.cleanup('census', first)
        self.assertIs(result[0], first)
        self.assertEqual([x for x in events if isinstance(x, int)], [15, 9])

    def test_echild_prevents_signal(self):
        events, result, _ = self.cleanup('echild')
        self.assertEqual([x for x in events if isinstance(x, int)], [])
        self.assertNotIn('waitpid', events)
        self.assertFalse(result[2])

    def test_identity_loss_prevents_signal(self):
        events, result, _ = self.cleanup('identity')
        self.assertEqual([x for x in events if isinstance(x, int)], [])
        self.assertNotIn('waitpid', events)
        self.assertFalse(result[2])

    def inventory(self, initial_visits, directory=False):
        events = []
        account = NS(metadata_visits=initial_visits)
        preparation = NS(root=NS(descriptor=42), scans=())

        class Entries:
            def __enter__(self):
                return iter((NS(name='entry', stat=self.entry_stat),))

            def __exit__(self, *args):
                return False

            def entry_stat(self, *, follow_symlinks):
                events.append(('stat', account.metadata_visits))
                return NS(st_mode=stat.S_IFDIR if directory else stat.S_IFREG, st_size=0)

        def scandir(descriptor):
            events.append(('scandir', account.metadata_visits))
            return Entries()

        def open_directory(*args, **kwargs):
            events.append(('open', account.metadata_visits))
            raise AssertionError('directory open was not refused at the budget boundary')

        from contextlib import nullcontext
        namespace = dict(account=account, preparation=preparation, clock=lambda: None,
                         _ORIGINAL_WORK_CAP=512*1024*1024, _ORIGINAL_METADATA_VISITS=128000,
            _ORIGINAL_READ_CAP=255*1024*1024,
                         _original_r_require=require, stat=stat, MIB=1024 * 1024,
                         _original_r_registration=nullcontext,
                         os=NS(scandir=scandir, fsencode=lambda s: s.encode(),
                               open=open_directory, O_RDONLY=0, O_DIRECTORY=0, O_NOFOLLOW=0))
        for name in ('visit', 'inventory'):
            exec(compile(segment(nested(PREP, name)), str(SOURCE), 'exec'), namespace)
        error = None
        try:
            namespace['inventory']()
        except Refusal as caught:
            error = caught
        return events, account.metadata_visits, preparation.scans, error

    def test_metadata_exhaustion_refuses_before_stat(self):
        events, visits, scans, error = self.inventory(127998)
        self.assertIsInstance(error, Refusal)
        self.assertEqual(events, [('scandir', 127999)])
        self.assertEqual(visits, 128000)
        self.assertEqual(scans, ())

    def test_regular_entry_has_separate_stat_debit(self):
        events, visits, scans, error = self.inventory(127996)
        self.assertIsNone(error)
        self.assertEqual(events, [('scandir', 127997), ('stat', 127999)])
        self.assertEqual(visits, 128000)
        self.assertEqual(scans, ((1, 0),))

    def test_metadata_exhaustion_refuses_before_directory_open(self):
        events, visits, scans, error = self.inventory(127997, directory=True)
        self.assertIsInstance(error, Refusal)
        self.assertEqual(events, [('scandir', 127998), ('stat', 128000)])
        self.assertEqual(visits, 128000)
        self.assertEqual(scans, ())


if __name__ == '__main__':
    print('Synthetic control-flow/accounting tests. No real Git/Linux/native credit.', flush=True)
    print(f'Source {SOURCE} bytes={len(RAW)} sha256={hashlib.sha256(RAW).hexdigest()}', flush=True)
    unittest.main(verbosity=2)
