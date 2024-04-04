import socket
import sys

from requests import adapters
from requests import exceptions as r_exceptions
from urllib3.connection import HTTPConnection

from vinfra import api_versions
from vinfra import exceptions
from vinfra.api import base
from vinfra.compat import PLATFORM_LINUX

try:
    TCP_USER_TIMEOUT = socket.TCP_USER_TIMEOUT
except AttributeError:
    TCP_USER_TIMEOUT = 18


class LinuxHTTPAdapter(adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):  # pylint: disable=arguments-differ
        options = list(HTTPConnection.default_socket_options)
        options.extend([
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
            (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5),
            (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3),
            # TCP_USER_TIMEOUT overtakes keepalive TCP_KEEPCNT
            # (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3),
            (socket.IPPROTO_TCP, TCP_USER_TIMEOUT, 5)
        ])
        kwargs['socket_options'] = options
        return super(LinuxHTTPAdapter, self).init_poolmanager(*args, **kwargs)


class HaTask(base.BackendTask):
    def __init__(self, api, data):
        super(HaTask, self).__init__(api, data, connect_retries=8,
                                     connect_retry_delay=0.5)

    def wait(self, timeout=None):
        if sys.platform != PLATFORM_LINUX:
            return super(HaTask, self).wait(timeout=timeout)

        # replace global adapter can have some affect to parallel runs
        adapter_prefix = 'https://'
        adapter = self.api.session.session.get_adapter(adapter_prefix)
        try:
            self.api.session.session.close()
            self.api.session.session.mount(adapter_prefix, LinuxHTTPAdapter())
            return super(HaTask, self).wait(timeout=timeout)
        finally:
            self.api.session.session.mount(adapter_prefix, adapter)


class HaPrimarySwitcher(base.PollTask):
    def __init__(self, resource, api, new_master):
        self.resource = resource
        self.api = api
        self._new_master = new_master

    def wait(self, timeout=None):
        timeout = timeout or self.default_timeout
        try:
            resource = super(HaPrimarySwitcher, self).wait(timeout=timeout)
        except exceptions.TimeoutError:
            msg = (
                "Failed to switch primary node to {}. Timeout of {} "
                "seconds exceeded".format(self._new_master, timeout)
            )
            raise exceptions.TimeoutError(msg)
        return resource

    def poll(self):
        try:
            self.resource = self.api.client.get("ha/configs")
        except r_exceptions.HTTPError as err:
            if err.response.status_code != 502:
                msg = (
                    "Failed to get HA primary switch status (HTTP code: {}).".format(
                        self.resource.status_code)
                )
                raise exceptions.VinfraError(msg)
            return None
        except (r_exceptions.ConnectionError, r_exceptions.ReadTimeout):
            return None

        primary = [x for x in self.resource['nodes'] if x['is_primary']][0]

        if primary['id'] == self._new_master:
            return self.resource

    def get_info(self):
        return self.resource


class HaConfig(object):
    def __init__(self, api):
        self.api = api

    def get(self):
        ha_config = self.api.client.get("/ha/configs")
        # Note(akurbatov): backend API returns empty response if ha is not
        # configured. Forcibly raise exception then:
        if not ha_config:
            raise exceptions.VinfraError("No HA configuration exists")
        return ha_config

    def create_async(self, nodes, virtual_ips, force=None):
        data = {
            'nodes': [base.get_id(node) for node in nodes],
            'virtual_ips': []
        }

        for network, ip_addr, addr_type in virtual_ips:
            vip = {
                'roles_set': base.get_id(network),
                'ip': str(ip_addr),
            }
            if addr_type and self.api.api_version >= api_versions.HCI_VER_35:
                vip['method'] = addr_type
            data['virtual_ips'].append(vip)

        if force is not None:
            data['force'] = force
        data = self.api.client.post("/ha/configs", json=data)
        return HaTask(self.api, data)

    def delete_async(self):
        data = self.api.client.delete("/ha/configs")
        return HaTask(self.api, data)

    def update_async(self, nodes=None, virtual_ips=None, force=None):
        data = {}
        if nodes:
            data['nodes'] = [base.get_id(node) for node in nodes]
        if virtual_ips:
            data['virtual_ips'] = []
            for network, ip_addr, addr_type in virtual_ips:
                vip = {
                    'roles_set': base.get_id(network),
                    'ip': str(ip_addr),
                }
                if (addr_type and
                        self.api.api_version >= api_versions.HCI_VER_35):
                    vip['method'] = addr_type
                data['virtual_ips'].append(vip)

        if force is not None:
            data['force'] = force

        data = self.api.client.patch("/ha/configs", json=data)
        return HaTask(self.api, data)

    def add_node_async(self, nodes, without_controller_service):
        data = {}
        if nodes:
            data['nodes'] = [base.get_id(node) for node in nodes]

        data['with_controller'] = not without_controller_service

        data = self.api.client.patch("/ha/nodes/", json=data)
        return HaTask(self.api, data)

    def remove_node_async(self, nodes, force=None):
        data = {}
        if nodes:
            data['nodes'] = [base.get_id(node) for node in nodes]

        if force is not None:
            data['force'] = force
        elif len(nodes) > 1:
            raise exceptions.VinfraError(
                "Multiple nodes can only be force removed by setting --force "
                "option")

        data = self.api.client.delete("/ha/nodes/", json=data)
        return HaTask(self.api, data)

    def switch_master_async(self, node):
        new_master = {'id': str(base.get_id(node))}
        resource = self.api.client.post("/ha/switch-master", json=new_master)
        return HaPrimarySwitcher(resource, self.api, new_master['id'])
