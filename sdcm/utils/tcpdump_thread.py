import threading
import time
import os
from contextlib import suppress
from typing import List

from sdcm.utils.decorators import retrying


class TCPDumpFile(threading.Thread):
    _uploaded = False

    def __init__(self, node, source_file: str, target_file: str):
        self._node = node
        self._source_file = source_file
        self._target_file = target_file
        super().__init__(daemon=True)

    def run(self):
        with suppress(Exception):
            self.upload()
        self.cleanup()

    def cleanup(self):
        with suppress(Exception):
            self._node.remoter.sudo(f'rm -f {self._source_file}')

    @retrying(n=5)
    def upload(self):
        try:
            self._node.remoter.receive_files(self._source_file, self._target_file)
            self._uploaded = True
        except Exception as exc:
            print(str(exc))

    @property
    def uploaded(self):
        return self._uploaded


class LogsWatcher(threading.Thread):
    _triggers = ['rpc - client [0-9.]+:7000: ']

    def __init__(self):
        self._nodes = []
        super().__init__(daemon=True)

    def add_node(self, node):
        self._nodes.append(node)

    def get_follower(self):
        followers = {}

        def inner():
            result = False
            for node in self._nodes:
                if node not in followers:
                    followers[node] = node.follow_system_log(patterns=self._triggers)
            for follower in followers.values():
                if list(follower):
                    result = True
            return result

        return inner


class TCPDumpThread(threading.Thread):
    _tcpdump_timestamp: float
    _tcpdump_path: str
    _tcpdump_thread: threading.Thread
    _files: List[TCPDumpFile]
    _log_watcher: LogsWatcher = None

    def __init__(self, node):
        self._log_watching_thread = threading.Thread()
        self._stop_event = threading.Event()
        if self.__class__._log_watcher is None:
            self.__class__._log_watcher = LogsWatcher()
        self._log_watcher.add_node(node)
        self._was_triggered = self._log_watcher.get_follower()
        self._node = node
        self._issue_spotted = False
        self._files = []
        super().__init__(daemon=True)

    def _install_tcpdump(self):
        self._node.remoter.run('yum install -y tcpdump')

    @property
    def _did_trigger_fire(self) -> bool:
        return self._was_triggered()

    def run(self):
        self.start_tcpdump()
        while not self._stop_event.wait(5):
            if self._did_trigger_fire:
                self._issue_spotted = True
                continue
            self.stop_tcpdump()
            old_path = self._tcpdump_path
            if not self._stop_event.is_set():
                self.start_tcpdump()
            if self._issue_spotted:
                self._node.remoter.sudo(f'mv {old_path} /tmp/tcpdump.{self._tcpdump_timestamp}')
                self._node.remoter.sudo(f'chmod 777 /tmp/tcpdump.{self._tcpdump_timestamp}')
                self.submit_file_to_process(f'/tmp/tcpdump.{self._tcpdump_timestamp}')
            else:
                self._node.remoter.sudo(f'rm -f {old_path}')
            self._issue_spotted = False

    def submit_file_to_process(self, file_path):
        file = TCPDumpFile(
            self._node,
            file_path,
            os.path.join(self._node.logdir, f'tcpdump.{self._tcpdump_timestamp}')
        )
        file.start()
        self._files.append(file)

    def start_tcpdump(self):
        with suppress(Exception):
            self._install_tcpdump()
        self._tcpdump_timestamp = time.time()
        self._tcpdump_path = f'/var/lib/scylla/tcpdump.{self._tcpdump_timestamp}'
        self._tcpdump_thread = threading.Thread(target=self._tcpdump_thread_body, daemon=True)
        self._tcpdump_thread.start()

    def _tcpdump_thread_body(self):
        self._node.remoter.sudo(f'touch {self._tcpdump_path}')
        self._node.remoter.sudo(f'/root/bin/tcpdump -B 50 -Z root -i any port 7000 -nw {self._tcpdump_path}')

    def stop_tcpdump(self):
        with suppress(Exception):
            self._node.remoter.sudo(f"pkill -f {self._tcpdump_path}", ignore_status=True)
            self._tcpdump_thread.join()

    def stop(self, timeout=None):
        self._stop_event.set()
        self.stop_tcpdump()
        self._tcpdump_thread.join(timeout)
        for tcpdump_file in self._files:
            tcpdump_file.join(10)
            tcpdump_file.cleanup()

