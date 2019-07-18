import json
import time
import logging
import os

import cluster
from sdcm.utils.common import retrying
from remote import LocalCmdRunner

logger = logging.getLogger(__name__)
localrunner = LocalCmdRunner()

BASE_NAME = 'db-node'
LOADER_NAME = 'loader-node'
MONITOR_NAME = 'monitor-node'


class DockerCommandError(Exception):
    pass


class DockerContainerNotExists(Exception):
    pass


class DockerContainerNotRunning(Exception):
    pass


class CannotFindContainers(Exception):
    pass


def _cmd(cmd, timeout=10, sudo=False):
    res = localrunner.run('docker {}'.format(cmd), ignore_status=True, timeout=timeout, sudo=sudo)
    if res.exit_status:
        if 'No such container:' in res.stderr:
            raise DockerContainerNotExists(res.stderr)
        raise DockerCommandError('command: {}, error: {}, output: {}'.format(cmd, res.stderr, res.stdout))
    return res.stdout


class DockerNode(cluster.BaseNode):

    def __init__(self, name, credentials, parent_cluster, base_logdir=None, node_prefix=None):
        ssh_login_info = {'hostname': None,
                          'user': 'scylla-test',
                          'key_file': credentials.key_file}
        super(DockerNode, self).__init__(name=name,
                                         parent_cluster=parent_cluster,
                                         base_logdir=base_logdir,
                                         ssh_login_info=ssh_login_info,
                                         node_prefix=node_prefix)
        self.wait_for_status_running()
        self.wait_public_ip()

    def _get_public_ip_address(self):
        if not self._public_ip_address:
            out = _cmd("inspect --format='{{{{ .NetworkSettings.IPAddress }}}}' {}".format(self.name))
            self._public_ip_address = out.strip()
        return self._public_ip_address

    def is_running(self):
        out = _cmd("inspect --format='{{{{json .State.Running}}}}' {}".format(self.name))
        return json.loads(out)

    @retrying(n=10, sleep_time=2, allowed_exceptions=(DockerContainerNotRunning,))
    def wait_for_status_running(self):
        if not self.is_running():
            raise DockerContainerNotRunning(self.name)

    @property
    def public_ip_address(self):
        return self._get_public_ip_address()

    @property
    def private_ip_address(self):
        return self._get_public_ip_address()

    def run_nodetool(self, sub_cmd, args="", options="", ignore_status=False):
        cmd = self._gen_nodetool_cmd(sub_cmd, args, options)
        logger.debug('run nodetool %s' % cmd)
        return _cmd('exec {} {}'.format(self.name, cmd))

    def wait_public_ip(self):
        while not self._public_ip_address:
            self._get_public_ip_address()
            time.sleep(1)

    def start(self):
        _cmd('start {}'.format(self.name))

    def restart(self, timeout=30):
        _cmd('restart {}'.format(self.name), timeout=timeout)

    def stop(self, timeout=30):
        _cmd('stop {}'.format(self.name), timeout=timeout)

    def destroy(self, force=True):
        force_param = '-f' if force else ''
        _cmd('rm {} -v {}'.format(force_param, self.name))


class DockerCluster(cluster.BaseCluster):

    def __init__(self, **kwargs):
        self._image = kwargs.get('docker_image', 'scylladb/scylla-nightly')
        self.nodes = []
        self.credentials = kwargs.get('credentials')
        self._node_prefix = kwargs.get('node_prefix')
        self._node_img_tag = 'scylla-sct-img'
        self._context_path = os.path.join(os.path.dirname(__file__), '../docker/scylla-sct')
        self._create_node_image()
        super(DockerCluster, self).__init__(node_prefix=self._node_prefix,
                                            n_nodes=kwargs.get('n_nodes'),
                                            params=kwargs.get('params'),
                                            region_names=["localhost-dc"])  # no multi dc currently supported

    def _create_node_image(self):
        self._update_image()
        _cmd('build --build-arg SOURCE_IMAGE={} -t {} {}'.format(self._image, self._node_img_tag, self._context_path),
             timeout=300)

    def _clean_old_images(self):
        images = _cmd('images -f "dangling=true" -q')
        if images:
            _cmd('rmi {}'.format(images), timeout=90)

    def _update_image(self):
        logger.debug('update scylla image')
        _cmd('pull {}'.format(self._image), timeout=300)
        self._clean_old_images()

    def _create_container(self, node_name, is_seed=False, seed_ip=None):
        cmd = 'run --name {} -d {}'.format(node_name, self._node_img_tag)
        if not is_seed and seed_ip:
            cmd = '{} --seeds="{}"'.format(cmd, seed_ip)
        _cmd(cmd, timeout=30)

    def _get_containers_by_prefix(self):
        c_ids = _cmd('container ls -a -q --filter name={}'.format(self._node_prefix))
        if not c_ids:
            raise CannotFindContainers('name prefix: %s' % self._node_prefix)
        return [_ for _ in c_ids.split('\n') if _]

    @staticmethod
    def _get_connainer_name_by_id(c_id):
        return json.loads(_cmd("inspect --format='{{{{json .Name}}}}' {}".format(c_id))).lstrip('/')

    def _create_node(self, node_name):
        return DockerNode(node_name,
                          credentials=self.credentials[0],
                          parent_cluster=self,
                          base_logdir=self.logdir,
                          node_prefix=self.node_prefix)

    def _get_node_name_and_index(self):
        """Is important when node is added to replace some dead node"""
        node_names = [node.name for node in self.nodes]
        node_index = 0
        while True:
            node_name = '%s-%s' % (self.node_prefix, node_index)
            if node_name not in node_names:
                return node_name, node_index
            node_index += 1

    def _create_nodes(self, count, dc_idx=0, enable_auto_bootstrap=False):
        """
        Create nodes from docker containers
        :param count: count of nodes to create
        :param dc_idx: datacenter index
        :return: list of DockerNode objects
        """
        new_nodes = []
        for _ in xrange(count):
            node_name, node_index = self._get_node_name_and_index()
            is_seed = (node_index == 0)
            seed_ip = self.nodes[0].public_ip_address if not is_seed else None
            self._create_container(node_name, is_seed, seed_ip)
            new_node = self._create_node(node_name)
            new_node.enable_auto_bootstrap = enable_auto_bootstrap
            self.nodes.append(new_node)
            new_nodes.append(new_node)
        return new_nodes

    def _get_nodes(self):
        """
        Find the existing containers by node name prefix
        and create nodes from it.
        :return: list of DockerNode objects
        """
        c_ids = self._get_containers_by_prefix()
        for c_id in c_ids:
            node_name = self._get_connainer_name_by_id(c_id)
            logger.debug('Node name: %s' % node_name)
            new_node = self._create_node(node_name)
            if not new_node.is_running():
                new_node.start()
                new_node.wait_for_status_running()
            self.nodes.append(new_node)
        return self.nodes

    def add_nodes(self, count, dc_idx=0, enable_auto_bootstrap=False):
        if cluster.Setup.REUSE_CLUSTER:
            return self._get_nodes()
        else:
            return self._create_nodes(count, dc_idx, enable_auto_bootstrap)

    def destroy(self):
        logger.info('Destroy nodes')
        for node in self.nodes:
            node.destroy(force=True)


class ScyllaDockerCluster(DockerCluster, cluster.BaseScyllaCluster):

    def __init__(self, **kwargs):
        self._user_prefix = kwargs.get('user_prefix', cluster.DEFAULT_USER_PREFIX)
        self._node_prefix = '%s-%s' % (self._user_prefix, BASE_NAME)
        super(ScyllaDockerCluster, self).__init__(node_prefix=kwargs.get('node_prefix', self._node_prefix),
                                                  **kwargs)

    @retrying(n=30, sleep_time=3, allowed_exceptions=(cluster.ClusterNodesNotReady, DockerCommandError))
    def wait_for_init(self, node_list=None, verbose=False, timeout=None):
        node_list = node_list if node_list else self.nodes
        for node in node_list:
            node.wait_for_status_running()
        return self.check_nodes_up_and_normal(node_list)


class LoaderSetDocker(cluster.BaseLoaderSet, DockerCluster):

    def __init__(self, **kwargs):
        self._node_prefix = '%s-%s' % (kwargs.get('user_prefix', cluster.DEFAULT_USER_PREFIX), LOADER_NAME)
        cluster.BaseLoaderSet.__init__(self,
                                       params=kwargs.get("params"))
        DockerCluster.__init__(self, node_prefix=self._node_prefix, **kwargs)


class MonitorSetDocker(DockerCluster, cluster.BaseMonitorSet):

    def __init__(self, **kwargs):
        self._node_prefix = '%s-%s' % (kwargs.get('user_prefix', cluster.DEFAULT_USER_PREFIX), MONITOR_NAME)
        super(MonitorSetDocker, self).__init__(node_prefix=self._node_prefix, **kwargs)
