# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See LICENSE for more details.
#
# Copyright (c) 2020 ScyllaDB

import time
from typing import Any, Optional, Sequence
from traceback import format_stack

from sdcm.sct_events import Severity
from sdcm.sct_events.base import SctEvent, SystemEvent


class StartupTestEvent(SystemEvent):
    def __init__(self):
        super().__init__(severity=Severity.NORMAL)


class TestTimeoutEvent(SctEvent):
    def __init__(self, start_time: float, duration: int):
        super().__init__(severity=Severity.CRITICAL)
        self.start_time = start_time
        self.duration = duration

    @property
    def msgfmt(self) -> str:
        start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.start_time))
        return f"{super().msgfmt}, Test started at {start_time}, reached it's timeout ({self.duration} minute)"


class TestFrameworkEvent(SctEvent):  # pylint: disable=too-many-instance-attributes
    __test__ = False  # Mark this class to be not collected by pytest.

    def __init__(self,
                 source: Any,
                 source_method: Optional = None,
                 args: Optional[Sequence] = None,
                 kwargs: Optional[dict] = None,
                 message: Optional = None,
                 exception: Optional = None,
                 trace: Optional = None,
                 severity: Optional[Severity] = None):

        if severity is None:
            severity = Severity.ERROR
        super().__init__(severity=severity)

        self.source = str(source) if source else None
        self.source_method = str(source_method) if source_method else None
        self.exception = str(exception) if exception else None
        self.message = str(message) if message else None
        self.trace = "".join(format_stack(trace)) if trace else None
        self.args = args
        self.kwargs = kwargs

    @property
    def msgfmt(self) -> str:
        fmt = super().msgfmt + ", source={0.source}"

        if self.source_method:
            args = []
            if self.args:
                args.append("args={0.args}")
            if self.kwargs:
                args.append("kwargs={0.kwargs}")
            fmt += ".{0.source_method}(" + ", ".join(args) + ")"

        if self.message:
            fmt += " message={0.message}"
        if self.exception:
            fmt += "\nexception={0.exception}"
        if self.trace:
            fmt += "\nTraceback (most recent call last):\n{0.trace}"

        return fmt


class SpotTerminationEvent(SctEvent):
    def __init__(self, node: Any, message: str):
        super().__init__(severity=Severity.CRITICAL)

        self.node = str(node)
        self.message = message

    @property
    def msgfmt(self) -> str:
        return super().msgfmt + ": node={0.node} message={0.message}"


class InfoEvent(SctEvent):
    def __init__(self, message: str):
        super().__init__(severity=Severity.NORMAL)

        self.message = message

    @property
    def msgfmt(self) -> str:
        return super().msgfmt + ": message={0.message}"


class ThreadFailedEvent(SctEvent):
    def __init__(self, message: str, traceback: Any):
        super().__init__(severity=Severity.ERROR)

        self.message = message
        self.traceback = str(traceback)

    @property
    def msgfmt(self) -> str:
        return super().msgfmt + ": message={0.message}\n{0.traceback}"


class CoreDumpEvent(SctEvent):
    def __init__(self,
                 node: Any,
                 corefile_url: str,
                 backtrace: str,
                 download_instructions: str,
                 timestamp: Optional[float] = None):

        super().__init__(severity=Severity.ERROR)

        self.node = str(node)
        self.corefile_url = corefile_url
        self.backtrace = backtrace
        self.download_instructions = download_instructions

        if timestamp is not None:
            self.timestamp = timestamp

    @property
    def msgfmt(self) -> str:
        fmt = super().msgfmt + " "

        if self.node:
            fmt += "node={0.node}\n"
        if self.corefile_url:
            fmt += "corefile_url={0.corefile_url}\n"
        if self.backtrace:
            fmt += "backtrace={0.backtrace}\n"
        if self.download_instructions:
            fmt += "download_instructions={0.download_instructions}\n"

        return fmt


class TestResultEvent(SctEvent, Exception):
    """An event that is published and raised at the end of the test.

    It holds and displays all errors of the tests and framework happened.
    """
    __test__ = False  # Mark this class to be not collected by pytest.

    _marker_width = 80
    _head = f"{' TEST RESULTS ':=^{_marker_width}}"
    _ending = "=" * _marker_width

    def __init__(self, test_status: str, events: dict, timestamp: Optional[float] = None):
        self._ok = test_status == "SUCCESS"
        super().__init__(severity=Severity.NORMAL if self._ok else Severity.ERROR)

        self.test_status = test_status
        self.events = events

        # Need to restore the timestamp on unpickling.  See `__reduce__()' also.
        if timestamp is not None:
            self.timestamp = timestamp

        # We don't publish this event.  Suppress warning about unpublished event on exit.
        self._ready_to_publish = False

    @property
    def events_formatted(self) -> str:
        result = []
        for event_group, events in self.events.items():
            if not events:
                continue
            result.append(f"""{f'{"":-<5} LAST {event_group} EVENT ':-<{self._marker_width - 2}}""")
            result.extend(events)
        return "\n".join(result)

    @property
    def msgfmt(self) -> str:
        if self._ok:
            return "{0._head}\n{0._ending}\nSUCCESS :)\n"
        return "{0._head}\n\n{0.events_formatted}\n{0._ending}\n{0.test_status} :(\n"

    def __reduce__(self):
        """Need to define it for pickling because of Exception class in MRO."""

        return type(self), (self.test_status, self.events, self.timestamp)
