from os.path import join as urljoin

from vinfra.api import base
from vinfra.utils import flatten_args


class Filebeat(base.Resource):
    ID_ATTR = 'id'
    NAME_ATTR = 'name'


class FilebeatManager(base.Manager):
    resource_class = Filebeat
    base_url = "/filebeat/nodes/{}/"

    def put_elasticsearch_options_on_node(
            self, node, host, port, username, password, restart_required
    ):
        node_id = base.get_id(node)
        url = urljoin(
            self.base_url.format(node_id), 'config/template_elasticsearch'
        )
        json = flatten_args(
            host=host, port=port, username=username,
            password=password, restart_required=restart_required
        )
        return self._put_async(url, json=json)

    def put_raw_config_on_node(self, node, config, restart_required):
        node_id = base.get_id(node)
        url = urljoin(self.base_url.format(node_id), 'config')
        return self._put_async(
            url, json=dict(raw_config=config, restart_required=restart_required)
        )

    def get(self, node):
        node_id = base.get_id(node)
        url = urljoin(self.base_url.format(node_id), 'service/show')
        return self._get(url)

    def start_async(self, node_id):
        url = urljoin(self.base_url.format(node_id), 'service/start')
        return self._post_async(url)

    def stop_async(self, node_id):
        url = urljoin(self.base_url.format(node_id), 'service/stop')
        return self._post_async(url)

    def restart_async(self, node_id):
        url = urljoin(self.base_url.format(node_id), 'service/restart')
        return self._post_async(url)

    def enable_async(self, node_id):
        url = urljoin(self.base_url.format(node_id), 'service/enable')
        return self._post_async(url)

    def disable_async(self, node_id):
        url = urljoin(self.base_url.format(node_id), 'service/disable')
        return self._post_async(url)
