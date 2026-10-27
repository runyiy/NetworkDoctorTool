import subprocess
from unittest.mock import MagicMock, patch

import pytest

from losshound.core import subprocess_runner


def _running_process(pid=1234):
    proc = MagicMock()
    proc.pid = pid
    proc.poll.return_value = None
    return proc


def test_failed_taskkill_falls_back_to_terminate():
    proc = _running_process()
    with patch.object(subprocess_runner.sys, "platform", "win32"), \
         patch.object(
             subprocess_runner.subprocess,
             "run",
             return_value=subprocess.CompletedProcess([], 1),
         ):
        subprocess_runner._terminate_process_tree(proc)

    proc.terminate.assert_called_once()


def test_successful_taskkill_waits_for_process_exit():
    proc = _running_process()
    proc.poll.side_effect = [None, 0]
    with patch.object(subprocess_runner.sys, "platform", "win32"), \
         patch.object(
             subprocess_runner.subprocess,
             "run",
             return_value=subprocess.CompletedProcess([], 0),
         ):
        subprocess_runner._terminate_process_tree(proc)

    proc.wait.assert_called_once_with(timeout=1.0)
    proc.terminate.assert_not_called()


def test_keyboard_interrupt_still_cleans_up_child():
    proc = _running_process()
    with patch.object(subprocess_runner.subprocess, "Popen", return_value=proc), \
         patch.object(
             subprocess_runner.QThread,
             "currentThread",
             side_effect=KeyboardInterrupt,
         ), \
         patch.object(subprocess_runner, "_terminate_process_tree") as terminate:
        with pytest.raises(KeyboardInterrupt):
            subprocess_runner.run_subprocess_interruptible(["ping"], 5)

    terminate.assert_called_once_with(proc)
