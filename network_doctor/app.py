"""Desktop interface for Network Doctor."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from queue import Empty
from tkinter import ttk

from network_doctor.analysis import format_report
from network_doctor.diagnostics import run_diagnosis


class NetworkDoctorApp:
    """Build the Network Doctor desktop window without starting a diagnosis."""

    def __init__(self, root: tk.Tk, diagnosis_runner=run_diagnosis) -> None:
        self.root = root
        self.diagnosis_runner = diagnosis_runner
        self._messages: queue.Queue[tuple[object, ...]] = queue.Queue()
        self._closing = False
        self._polling = False
        self._report_text = ""
        self._worker: threading.Thread | None = None

        root.title("NetworkDoctor")
        root.geometry("760x560")
        root.minsize(760, 560)

        container = ttk.Frame(root, padding=16)
        container.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(2, weight=1)

        self.status_var = tk.StringVar(value="准备就绪")
        self.status_label = ttk.Label(container, textvariable=self.status_var)
        self.status_label.grid(row=0, column=0, sticky="w")

        self.progress = ttk.Progressbar(container, mode="determinate", maximum=100)
        self.progress.grid(row=1, column=0, sticky="ew", pady=(8, 12))

        output_frame = ttk.Frame(container)
        output_frame.grid(row=2, column=0, sticky="nsew")
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        self.output = tk.Text(output_frame, wrap="word", height=20)
        self.output.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(output_frame, command=self.output.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.output.configure(yscrollcommand=scrollbar.set)

        buttons = ttk.Frame(container)
        buttons.grid(row=3, column=0, sticky="e", pady=(12, 0))
        self.start_button = ttk.Button(buttons, text="开始诊断", command=self.start_diagnosis)
        self.start_button.grid(row=0, column=0, padx=(0, 8))
        self.copy_button = ttk.Button(
            buttons, text="复制结果", command=self.copy_result, state="disabled"
        )
        self.copy_button.grid(row=0, column=1)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

    def start_diagnosis(self) -> None:
        """Start one diagnosis worker while keeping Tk work on the event loop."""
        if self._closing or (self._worker is not None and self._worker.is_alive()):
            return

        self.start_button.configure(state="disabled")
        self.copy_button.configure(state="disabled")
        self.output.delete("1.0", tk.END)
        self.status_var.set("正在准备诊断……")
        self.progress["value"] = 0

        def progress(text: str, percent: int) -> None:
            self._messages.put(("progress", text, percent))

        def run_worker() -> None:
            try:
                report = self.diagnosis_runner(on_progress=progress)
            except Exception as error:
                self._messages.put(("error", str(error)))
            else:
                self._messages.put(("result", report))

        self._worker = threading.Thread(target=run_worker, daemon=True)
        self._worker.start()
        self._polling = True
        self.root.after(80, self._drain_queue)

    def copy_result(self) -> None:
        """Copy the latest completed report at the operating-system clipboard boundary."""
        self.root.clipboard_clear()
        self.root.clipboard_append(self._report_text)

    def _on_close(self) -> None:
        self._closing = True
        self._polling = False
        self.root.destroy()

    def _drain_queue(self) -> None:
        """Apply worker messages on Tk's event-loop thread."""
        if self._closing:
            return

        completed = False
        while True:
            try:
                message = self._messages.get_nowait()
            except Empty:
                break

            kind, *payload = message
            if kind == "progress":
                text, percent = payload
                self.status_var.set(text)
                self.progress["value"] = percent
            elif kind == "result":
                report = payload[0]
                self._report_text = format_report(report)
                self.output.delete("1.0", tk.END)
                self.output.insert(tk.END, self._report_text)
                self.status_var.set("诊断完成")
                self.progress["value"] = 100
                self.progress.stop()
                self.start_button.configure(state="normal", text="重新诊断")
                self.copy_button.configure(state="normal")
                completed = True
            elif kind == "error":
                self.output.delete("1.0", tk.END)
                self.output.insert(tk.END, "诊断未完成\n请稍后重试。")
                self.status_var.set("诊断未完成")
                self.progress.stop()
                self.start_button.configure(state="normal")
                self.copy_button.configure(state="disabled")
                completed = True

        if completed:
            self._polling = False
        if self._polling and not self._closing:
            self.root.after(80, self._drain_queue)


def main() -> None:
    root = tk.Tk()
    NetworkDoctorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
