import importlib
import queue
import threading

from network_doctor.models import CheckState, DiagnosisReport, Finding


def test_app_import_does_not_start_tkinter():
    """Catches module import creating a Tk window or omitting the public UI API."""
    module = importlib.import_module("network_doctor.app")

    assert callable(module.main)
    assert module.NetworkDoctorApp.__name__ == "NetworkDoctorApp"


class FakeValue:
    def __init__(self, value=""):
        self.value = value

    def set(self, value):
        self.value = value


class FakeProgress:
    def __init__(self):
        self.value = 0
        self.stopped = False
        self.running = False

    def __setitem__(self, key, value):
        assert key == "value"
        self.value = value

    def stop(self):
        self.stopped = True
        self.running = False

    def start(self, interval):
        self.running = True


class FakeText:
    def __init__(self, content=""):
        self.content = content

    def delete(self, start, end):
        self.content = ""

    def insert(self, index, content):
        self.content += content


class FakeButton:
    def __init__(self, state="normal"):
        self.state = state

    def configure(self, **options):
        self.state = options.get("state", self.state)


class FakeRoot:
    def __init__(self):
        self.scheduled = []
        self.clipboard = ""
        self.destroyed = False

    def after(self, milliseconds, callback):
        self.scheduled.append((milliseconds, callback))

    def clipboard_clear(self):
        self.clipboard = ""

    def clipboard_append(self, content):
        self.clipboard += content

    def destroy(self):
        self.destroyed = True


def sample_report():
    return DiagnosisReport(
        overall=CheckState.OK,
        primary_problem="未发现明显网络问题",
        findings=(Finding(CheckState.OK, "网络适配器", "正在使用 Wi-Fi。"),),
        recommendations=("当前网络连接正常；如偶发问题再次出现，可重新运行诊断。",),
    )


def app_for_queue_tests():
    app_module = importlib.import_module("network_doctor.app")
    app = app_module.NetworkDoctorApp.__new__(app_module.NetworkDoctorApp)
    app.root = FakeRoot()
    app._messages = queue.Queue()
    app._closing = False
    app._polling = True
    app._worker = None
    app.status_var = FakeValue("准备就绪")
    app.progress = FakeProgress()
    app.output = FakeText()
    app.start_button = FakeButton("disabled")
    app.copy_button = FakeButton("disabled")
    return app


def test_drain_queue_applies_progress_to_status_and_bar():
    """Catches worker progress messages that never become visible in the UI."""
    app = app_for_queue_tests()
    app._messages.put(("progress", "正在测试默认网关……", 35))

    app._drain_queue()

    assert app.status_var.value == "正在测试默认网关……"
    assert app.progress.value == 35
    assert app.root.scheduled[0][0] == 80


def test_drain_queue_renders_result_and_reenables_actions():
    """Catches a completed diagnosis that leaves its report or UI actions unavailable."""
    app = app_for_queue_tests()
    report = sample_report()
    app._messages.put(("result", report))

    app._drain_queue()

    assert "总体结论" in app.output.content
    assert "未发现明显网络问题" in app.output.content
    assert app.start_button.state == "normal"
    assert app.copy_button.state == "normal"
    assert app.progress.stopped is True
    assert app.progress.value == 100
    assert app._polling is False
    assert app.root.scheduled == []


def test_drain_queue_shows_safe_error_message():
    """Catches an unexpected worker error exposing a traceback in the report area."""
    app = app_for_queue_tests()
    app._messages.put(("error", "probe failure"))

    app._drain_queue()

    assert "诊断未完成" in app.output.content
    assert "Traceback" not in app.output.content
    assert app.start_button.state == "normal"
    assert app.copy_button.state == "disabled"


def test_drain_queue_ignores_pending_messages_after_close():
    """Catches a closing window being updated by a late worker message."""
    app = app_for_queue_tests()
    app._closing = True
    app._messages.put(("progress", "正在测试默认网关……", 35))

    app._drain_queue()

    assert app.status_var.value == "准备就绪"
    assert app.progress.value == 0
    assert app.root.scheduled == []


def test_start_diagnosis_runs_in_background_and_delivers_messages():
    """Catches a diagnosis run blocking the UI or leaving retry/copy controls enabled."""
    app = app_for_queue_tests()
    completed = threading.Event()

    def runner(*, on_progress):
        on_progress("正在分析结果……", 95)
        completed.set()
        return sample_report()

    app.diagnosis_runner = runner
    app.output.content = "previous report"

    app.start_diagnosis()

    assert app.start_button.state == "disabled"
    assert app.copy_button.state == "disabled"
    assert app.output.content == ""
    assert app.progress.running is False
    assert app.progress.value == 0
    assert completed.wait(timeout=1)
    app._worker.join(timeout=1)
    assert app._worker.is_alive() is False

    app._drain_queue()

    assert "总体结论" in app.output.content
    assert app.start_button.state == "normal"


def test_start_diagnosis_turns_worker_exception_into_safe_ui_error():
    """Catches a background diagnosis exception escaping instead of becoming a retryable error."""
    app = app_for_queue_tests()
    completed = threading.Event()

    def failing_runner(*, on_progress):
        completed.set()
        raise RuntimeError("probe failure")

    app.diagnosis_runner = failing_runner

    app.start_diagnosis()

    assert completed.wait(timeout=1)
    app._worker.join(timeout=1)
    assert app._worker.is_alive() is False
    app._drain_queue()

    assert "诊断未完成" in app.output.content
    assert "Traceback" not in app.output.content
    assert app.start_button.state == "normal"


def test_start_diagnosis_does_not_overlap_an_active_worker():
    """Catches a second start creating concurrent diagnostics while the first still runs."""
    app = app_for_queue_tests()
    entered = threading.Event()
    release = threading.Event()
    runs = []

    def blocked_runner(*, on_progress):
        runs.append("diagnosis")
        entered.set()
        assert release.wait(timeout=1)
        return sample_report()

    app.diagnosis_runner = blocked_runner
    app.start_diagnosis()
    assert entered.wait(timeout=1)

    app.start_diagnosis()
    release.set()
    app._worker.join(timeout=1)

    assert runs == ["diagnosis"]


def test_copy_result_places_the_rendered_report_on_clipboard():
    """Catches Copy Report omitting or corrupting the last rendered report."""
    app = app_for_queue_tests()
    app._report_text = "总体结论\n网络正常"

    app.copy_result()

    assert app.root.clipboard == "总体结论\n网络正常"


def test_close_marks_app_closed_before_destroying_root():
    """Catches a window close leaving queue updates scheduled against a destroyed root."""
    app = app_for_queue_tests()

    app._on_close()

    assert app._closing is True
    assert app.root.destroyed is True
