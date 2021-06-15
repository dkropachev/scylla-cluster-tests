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

import os
import time
import random
import logging
import uuid
import threading

from sdcm.stress_thread import format_stress_cmd_error, DockerBasedStressThread
from sdcm.utils.docker_remote import RemoteDocker
from sdcm.sct_events.system import InfoEvent
from sdcm.sct_events.loaders import NoSQLBenchStressEvent
from sdcm.cluster import BaseNode


LOGGER = logging.getLogger(__name__)


class NoSQLBenchStressThread(DockerBasedStressThread):  # pylint: disable=too-many-instance-attributes

    def run(self):
        _self = super().run()
        # wait for the KCL thread to create the tables, so the YCSB thread beat this one, and start failing
        return _self

    def build_stress_cmd(self):
        if hasattr(self.node_list[0], 'parent_cluster'):
            target_address = self.node_list[0].parent_cluster.get_node().ip_address
        else:
            target_address = self.node_list[0].ip_address
        stress_cmd, rest = self.stress_cmd.strip().split(maxsplit=1)
        assert stress_cmd == 'nosqlbench'
        return 'java -jar nb.jar ' + rest + f" hosts={target_address}"

    def _run_stress(self, loader, loader_idx, cpu_idx):
        docker = RemoteDocker(
            loader,
            "scylla0dkropachev/nosqlbench:latest",
            extra_docker_opts=f'--entrypoint /bin/sh --label shell_marker={self.shell_marker}',
            command_line='-c "sleep infinity"'
        )
        stress_cmd = self.build_stress_cmd()

        if not os.path.exists(loader.logdir):
            os.makedirs(loader.logdir, exist_ok=True)
        log_file_name = os.path.join(loader.logdir, 'kcl-l%s-c%s-%s.log' %
                                     (loader_idx, cpu_idx, uuid.uuid4()))
        LOGGER.debug('kcl-stress local log: %s', log_file_name)

        LOGGER.debug("'running: %s", stress_cmd)

        NoSQLBenchStressEvent.start(node=loader, stress_cmd=stress_cmd).publish()

        try:
            result = docker.run_plain(
                cmd=stress_cmd,
                timeout=self.timeout + self.shutdown_timeout,
                log_file=log_file_name,
            )

            return result

        except Exception as exc:  # pylint: disable=broad-except
            errors_str = format_stress_cmd_error(exc)
            NoSQLBenchStressEvent.failure(
                node=loader,
                stress_cmd=self.stress_cmd,
                log_file_name=log_file_name,
                errors=[errors_str, ],
            ).publish()
            raise
        finally:
            NoSQLBenchStressEvent.finish(node=loader, stress_cmd=stress_cmd, log_file_name=log_file_name).publish()


class CompareTablesSizesThread(DockerBasedStressThread):  # pylint: disable=too-many-instance-attributes
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stop_event = threading.Event()

    def kill(self):
        self._stop_event.set()

    def db_node_to_query(self, loader):
        """Select DB node in the same region as loader node to query"""
        db_nodes = [db_node for db_node in self.node_list if not db_node.running_nemesis]
        assert db_nodes, "No node to query, nemesis runs on all DB nodes!"
        node_to_query = random.choice(db_nodes)
        LOGGER.debug(f"Selected '{node_to_query}' to query for local nodes")
        return node_to_query

    def _run_stress(self, loader, loader_idx, cpu_idx):
        NoSQLBenchStressEvent.start(node=loader, stress_cmd=self.stress_cmd).publish()
        try:
            options_str = self.stress_cmd.replace('table_compare', '').strip()
            options = dict(item.strip().split("=") for item in options_str.split(";"))
            interval = int(options.get('interval', 20))
            timeout = int(options.get('timeout', 28800))
            src_table = options.get('src_table')
            dst_table = options.get('dst_table')
            start_time = time.time()

            while not self._stop_event.is_set():
                node: BaseNode = self.db_node_to_query(loader)
                node.running_nemesis = "Compare tables size by cf-stats"
                node.run_nodetool('flush')

                dst_size = node.get_cfstats(dst_table)['Number of partitions (estimate)']
                src_size = node.get_cfstats(src_table)['Number of partitions (estimate)']

                node.running_nemesis = None
                elapsed_time = time.time() - start_time
                status = f"== CompareTablesSizesThread: dst table/src table number of partitions: {dst_size}/{src_size} =="
                LOGGER.info(status)
                status_msg = f'[{elapsed_time}/{timeout}] {status}'
                InfoEvent(status_msg).publish()

                if src_size == 0:
                    continue
                if elapsed_time > timeout:
                    InfoEvent(f"== CompareTablesSizesThread: exiting on timeout of {timeout}").publish()
                    break
                time.sleep(interval)
            return None

        except Exception as exc:  # pylint: disable=broad-except
            errors_str = format_stress_cmd_error(exc)
            NoSQLBenchStressEvent.failure(node=loader, stress_cmd=self.stress_cmd, errors=[errors_str, ]).publish()
            raise
        finally:
            NoSQLBenchStressEvent.finish(node=loader).publish()
