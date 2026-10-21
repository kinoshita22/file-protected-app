from __future__ import annotations

import sys
from pathlib import Path
from typing import List

from PyQt5.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from . import crypto

MIN_PASSWORD_LENGTH = 8


class Worker(QObject):
    """Encrypts or decrypts a list of files on a background thread."""

    file_started = pyqtSignal(int, str)
    file_progress = pyqtSignal(int)  # percent of the current file
    file_finished = pyqtSignal(str, bool, str)  # source, success, message
    finished = pyqtSignal(int, int)  # succeeded, failed

    def __init__(self, files: List[Path], password: str, encrypt: bool, depth: int, delete_originals: bool):
        super().__init__()
        self.files = files
        self.password = password
        self.encrypt = encrypt
        self.depth = depth
        self.delete_originals = delete_originals

    def _report(self, done: int, total: int) -> None:
        self.file_progress.emit(100 if total == 0 else int(done * 100 / total))

    def run(self) -> None:
        ok = failed = 0
        for i, src in enumerate(self.files):
            self.file_started.emit(i, str(src))
            try:
                if self.encrypt:
                    dst = crypto.encrypted_output_path(src)
                    crypto.encrypt_file(src, dst, self.password, self.depth, self._report)
                else:
                    dst = crypto.decrypted_output_path(src)
                    crypto.decrypt_file(src, dst, self.password, self._report)
                if self.delete_originals:
                    src.unlink()
                ok += 1
                self.file_finished.emit(str(src), True, f"→ {dst.name}")
            except Exception as exc:  # report per-file failures and keep going
                failed += 1
                self.file_finished.emit(str(src), False, str(exc))
        self.finished.emit(ok, failed)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Protect")
        self.resize(640, 640)
        self.thread: QThread | None = None
        self.worker: Worker | None = None
        self._current_index = 0

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self._build_files_group())
        layout.addWidget(self._build_options_group())
        layout.addWidget(self._build_password_group())

        self.run_button = QPushButton()
        self.run_button.setMinimumHeight(36)
        self.run_button.clicked.connect(self._start)
        layout.addWidget(self.run_button)

        self.progress = QProgressBar()
        self.progress.setFormat("%p%")
        layout.addWidget(self.progress)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(1000)
        self.log.setPlaceholderText("Results will appear here.")
        layout.addWidget(self.log, 1)

        self.setCentralWidget(central)
        self._mode_changed()

    # --- UI construction -------------------------------------------------

    def _build_files_group(self) -> QGroupBox:
        group = QGroupBox("Files")
        layout = QVBoxLayout(group)

        self.file_list = QListWidget()
        self.file_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.file_list.setMinimumHeight(120)
        layout.addWidget(self.file_list)

        buttons = QHBoxLayout()
        add = QPushButton("Add files…")
        add.clicked.connect(self._add_files)
        remove = QPushButton("Remove selected")
        remove.clicked.connect(self._remove_selected)
        clear = QPushButton("Clear")
        clear.clicked.connect(self.file_list.clear)
        self.file_buttons = (add, remove, clear)
        self.file_count = QLabel()
        for w in self.file_buttons:
            buttons.addWidget(w)
        buttons.addStretch(1)
        buttons.addWidget(self.file_count)
        layout.addLayout(buttons)

        model = self.file_list.model()
        model.rowsInserted.connect(self._update_file_count)
        model.rowsRemoved.connect(self._update_file_count)
        model.modelReset.connect(self._update_file_count)
        self._update_file_count()
        return group

    def _build_options_group(self) -> QGroupBox:
        group = QGroupBox("Options")
        form = QFormLayout(group)

        mode_row = QHBoxLayout()
        self.encrypt_radio = QRadioButton("Encrypt")
        self.decrypt_radio = QRadioButton("Decrypt")
        self.encrypt_radio.setChecked(True)
        self.mode_group = QButtonGroup(self)
        self.mode_group.addButton(self.encrypt_radio)
        self.mode_group.addButton(self.decrypt_radio)
        self.mode_group.buttonToggled.connect(self._mode_changed)
        mode_row.addWidget(self.encrypt_radio)
        mode_row.addWidget(self.decrypt_radio)
        mode_row.addStretch(1)
        form.addRow("Mode:", mode_row)

        self.depth_combo = QComboBox()
        for level, (label, log_n) in crypto.DEPTH_LEVELS.items():
            mib = 128 * 8 * 2**log_n // (1024 * 1024)
            self.depth_combo.addItem(f"{level} – {label} ({mib} MiB key derivation)", level)
        self.depth_combo.setCurrentIndex(self.depth_combo.findData(crypto.DEFAULT_DEPTH))
        self.depth_combo.setToolTip(
            "Higher depth makes password guessing much slower,\n"
            "at the cost of more time and memory per file."
        )
        self.depth_label = QLabel("Encryption depth:")
        form.addRow(self.depth_label, self.depth_combo)

        self.delete_check = QCheckBox("Delete original files after success")
        form.addRow("", self.delete_check)
        return group

    def _build_password_group(self) -> QGroupBox:
        group = QGroupBox("Password")
        form = QFormLayout(group)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.textChanged.connect(self._validate_passwords)
        form.addRow("Password:", self.password_edit)

        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        self.confirm_edit.textChanged.connect(self._validate_passwords)
        self.confirm_label = QLabel("Confirm password:")
        form.addRow(self.confirm_label, self.confirm_edit)

        self.show_password = QCheckBox("Show password")
        self.show_password.toggled.connect(self._toggle_echo)
        form.addRow("", self.show_password)

        self.password_hint = QLabel()
        self.password_hint.setWordWrap(True)
        form.addRow("", self.password_hint)
        return group

    # --- slots -----------------------------------------------------------

    def _add_files(self) -> None:
        if self.encrypt_radio.isChecked():
            filters = "All files (*)"
        else:
            filters = f"Encrypted files (*{crypto.EXTENSION});;All files (*)"
        paths, _ = QFileDialog.getOpenFileNames(self, "Select files", "", filters)
        existing = {self.file_list.item(i).text() for i in range(self.file_list.count())}
        for p in paths:
            if p not in existing:
                self.file_list.addItem(p)
                existing.add(p)

    def _remove_selected(self) -> None:
        for item in self.file_list.selectedItems():
            self.file_list.takeItem(self.file_list.row(item))

    def _update_file_count(self, *_) -> None:
        n = self.file_list.count()
        self.file_count.setText(f"{n} file{'s' if n != 1 else ''} selected")

    def _mode_changed(self, *_) -> None:
        encrypting = self.encrypt_radio.isChecked()
        self.run_button.setText("Encrypt files" if encrypting else "Decrypt files")
        # Depth is stored in the encrypted file, and decryption needs no confirmation.
        for w in (self.depth_combo, self.depth_label, self.confirm_edit, self.confirm_label):
            w.setEnabled(encrypting)
        if not encrypting:
            self.confirm_edit.clear()
        self._validate_passwords()

    def _toggle_echo(self, show: bool) -> None:
        mode = QLineEdit.Normal if show else QLineEdit.Password
        self.password_edit.setEchoMode(mode)
        self.confirm_edit.setEchoMode(mode)

    def _password_problem(self) -> str | None:
        pw = self.password_edit.text()
        if not pw:
            return "Enter a password."
        if self.encrypt_radio.isChecked():
            if len(pw) < MIN_PASSWORD_LENGTH:
                return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
            if pw != self.confirm_edit.text():
                return "Passwords do not match."
        return None

    def _validate_passwords(self, *_) -> None:
        problem = self._password_problem()
        if problem:
            self.password_hint.setStyleSheet("color: #c62828;")
            self.password_hint.setText(problem)
        else:
            self.password_hint.setStyleSheet("color: #2e7d32;")
            self.password_hint.setText("Password OK.")

    def _start(self) -> None:
        files = [Path(self.file_list.item(i).text()) for i in range(self.file_list.count())]
        if not files:
            QMessageBox.warning(self, "No files", "Add at least one file to process.")
            return
        problem = self._password_problem()
        if problem:
            QMessageBox.warning(self, "Password", problem)
            return

        encrypting = self.encrypt_radio.isChecked()
        if self.delete_check.isChecked():
            answer = QMessageBox.question(
                self,
                "Delete originals?",
                f"The {len(files)} original file(s) will be permanently deleted after "
                "they are processed successfully. Continue?",
            )
            if answer != QMessageBox.Yes:
                return

        self._set_busy(True)
        self.progress.setRange(0, len(files) * 100)
        self.progress.setValue(0)
        self.log.appendPlainText(f"--- {'Encrypting' if encrypting else 'Decrypting'} {len(files)} file(s) ---")

        self.thread = QThread(self)
        self.worker = Worker(
            files,
            self.password_edit.text(),
            encrypting,
            self.depth_combo.currentData(),
            self.delete_check.isChecked(),
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.file_started.connect(self._on_file_started)
        self.worker.file_progress.connect(self._on_file_progress)
        self.worker.file_finished.connect(self._on_file_finished)
        self.worker.finished.connect(self._on_finished)
        self.worker.finished.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.start()

    def _on_file_started(self, index: int, path: str) -> None:
        self._current_index = index
        self.statusBar().showMessage(f"Processing {Path(path).name}…")

    def _on_file_progress(self, percent: int) -> None:
        self.progress.setValue(self._current_index * 100 + percent)

    def _on_file_finished(self, path: str, success: bool, message: str) -> None:
        name = Path(path).name
        self.log.appendPlainText(f"✔ {name} {message}" if success else f"✘ {name}: {message}")

    def _on_finished(self, ok: int, failed: int) -> None:
        self.progress.setValue(self.progress.maximum())
        summary = f"Done: {ok} succeeded, {failed} failed."
        self.log.appendPlainText(summary)
        self.statusBar().showMessage(summary, 10000)
        self._set_busy(False)
        if failed == 0:
            self.file_list.clear()
            self.password_edit.clear()
            self.confirm_edit.clear()
            QMessageBox.information(self, "Finished", summary)
        else:
            QMessageBox.warning(self, "Finished with errors", summary + "\nSee the log for details.")

    def _set_busy(self, busy: bool) -> None:
        for w in (self.run_button, self.file_list, *self.file_buttons, self.encrypt_radio,
                  self.decrypt_radio, self.password_edit, self.delete_check):
            w.setEnabled(not busy)
        encrypting = self.encrypt_radio.isChecked()
        for w in (self.depth_combo, self.depth_label, self.confirm_edit, self.confirm_label):
            w.setEnabled(not busy and encrypting)
        self.setCursor(Qt.BusyCursor if busy else Qt.ArrowCursor)

    def closeEvent(self, event) -> None:
        if self.thread is not None and self.thread.isRunning():
            QMessageBox.information(self, "Busy", "Please wait for the current operation to finish.")
            event.ignore()
            return
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("File Protect")
    window = MainWindow()
    window.show()
    return app.exec_()
