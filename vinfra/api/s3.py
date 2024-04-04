import json

from vinfra import exceptions
from vinfra.api import base, failure_domains
from vinfra.api.compute.storage_policies import get_api_redundancy
from vinfra.utils import flatten_args


class S3Api(base.VinfraApi):
    def __init__(self, cluster):
        self.cluster = cluster
        self.replication = S3Replication(self.cluster)
        super(S3Api, self).__init__(cluster.manager.api)

    @property
    def base_url(self):
        return "/{}/s3".format(base.get_id(self.cluster))

    def get(self):
        with failure_domains.api_version(self.client):
            return self.client.get(self.base_url)

    def _adjust_nodes(self, nodes):
        # Note(akurbatov): backend has outdated API and requires to pass
        # exclusive ostor private interface. But ostor private iface can be
        # auto detected.
        ostor_private_traffic_type = 'OSTOR private'
        ostor_private_network = None
        for network in self.api.networks.list():
            if ostor_private_traffic_type in network.traffic_types:
                ostor_private_network = network
                break
        else:
            msg = "Network with {!r} traffic type not found".format(
                ostor_private_traffic_type)
            raise exceptions.VinfraError(msg)

        nodes_data = []
        for node in nodes:
            for iface in node.ifaces_manager.list():
                if iface.network == ostor_private_network.id:
                    nodes_data.append({
                        'id': base.get_id(node),
                        'priv_net_if': iface.name
                    })
                    break
            else:
                msg = "Traffic type {!r} is not assigned on node {!r}".format(
                    ostor_private_traffic_type, node)
                raise exceptions.VinfraError(msg)

        return nodes_data

    @staticmethod
    def _get_stream(stream):
        if not hasattr(stream, 'read'):
            try:
                stream = open(stream, 'rb')
            except Exception as err:
                raise exceptions.VinfraError(err)
        return stream

    # pylint: disable=too-many-arguments
    def create_async(self, nodes, s3gw_domain, tier, redundancy,
                     failure_domain, md_tier=None, md_redundancy=None, md_failure_domain=None,
                     s3gw_count=None, gen_cert=None, cert=None, key=None,
                     password=None, insecure=False, notary_provider=None,
                     n_os=None, n_ns=None, ignore_ram_reservation=False):
        nodes = self._adjust_nodes(nodes)
        redundancy = get_api_redundancy(redundancy)
        md_redundancy = get_api_redundancy(md_redundancy)

        if gen_cert or cert:
            scheme = 'https'
            if insecure:
                scheme += '_http'
        else:
            scheme = 'http'

        data = {
            'nodes': nodes,
            's3gw_domain': s3gw_domain,
            's3gw_count': s3gw_count,
            'tier': tier,
            'redundancy': redundancy,
            'failure_domain': failure_domain,
            'protocol': {
                'scheme': scheme,
                'password': password,
                'gen_cert': gen_cert,
            },
        }

        metadata_policy = {}
        if md_tier:
            metadata_policy['tier'] = md_tier
        if md_redundancy:
            metadata_policy['redundancy'] = md_redundancy
        if md_failure_domain:
            metadata_policy['failure_domain'] = md_failure_domain
        if metadata_policy:
            data['metadata_policy'] = metadata_policy

        if notary_provider:
            data['np'] = notary_provider
        if n_os is not None:
            data['n_os'] = n_os
        if n_ns is not None:
            data['n_ns'] = n_ns
        if ignore_ram_reservation:
            data['ignore_ram_reservation'] = ignore_ram_reservation
        files = {'json': (None, json.dumps(data))}
        if cert:
            files['cert'] = self._get_stream(cert)
        if key:
            files['key'] = self._get_stream(key)

        return self.client.post_async(self.base_url, files=files)

    def assign_nodes_async(self, nodes, ignore_ram_reservation=False, s3gw_count=None):
        data = {
            'nodes': self._adjust_nodes(nodes),
            's3gw_count': s3gw_count
        }
        if ignore_ram_reservation:
            data['ignore_ram_reservation'] = ignore_ram_reservation
        url = "{}/nodes/assign".format(self.base_url)
        return self.client.post_async(url, json=data)

    def change_nodes_async(self, nodes, s3gw_count):
        data = {
            'nodes': self._adjust_nodes(nodes)
        }
        data['s3gw_count'] = s3gw_count
        url = "{}/nodes/change".format(self.base_url)
        return self.client.post_async(url, json=data)

    def release_nodes_async(self, nodes):
        data = {
            'nodes': [base.get_id(node) for node in nodes],
        }
        url = "{}/nodes/release".format(self.base_url)
        return self.client.post_async(url, json=data)

    def change(
            self,
            failure_domain=None, tier=None, redundancy=None,
            md_tier=None, md_redundancy=None, md_failure_domain=None,
            gen_cert=None, cert=None, key=None, password=None,
            insecure=False, notary_provider=None, s3gw_count=None,
    ):
        redundancy = get_api_redundancy(redundancy)
        md_redundancy = get_api_redundancy(md_redundancy)
        protocol = None
        if any([gen_cert, cert, key, password, insecure]):
            if gen_cert or cert:
                scheme = 'https'
                if insecure:
                    scheme += '_http'
            else:
                scheme = 'http'
            protocol = {
                'scheme': scheme,
                'password': password,
                'gen_cert': gen_cert,
            }

        data = flatten_args(
            failure_domain=failure_domain,
            tier=tier,
            redundancy=redundancy,
            protocol=protocol,
            np=notary_provider,
            s3gw_count=s3gw_count,
        )

        metadata_policy = {}
        if md_tier:
            metadata_policy['tier'] = md_tier
        if md_redundancy:
            metadata_policy['redundancy'] = md_redundancy
        if md_failure_domain:
            metadata_policy['failure_domain'] = md_failure_domain
        if metadata_policy:
            data['metadata_policy'] = metadata_policy

        files = {'json': (None, json.dumps(data))}
        if cert:
            files['cert'] = self._get_stream(cert)
        if key:
            files['key'] = self._get_stream(key)
        return self.client.put_async(self.base_url, files=files)


class S3ReplicationNode(base.Resource):
    pass


class S3Replication(base.Manager):
    resource_class = S3ReplicationNode

    def __init__(self, cluster):
        self.cluster = cluster
        super(S3Replication, self).__init__(cluster.manager.api)

    @property
    def base_url(self):
        return "/{}/s3/geo".format(base.get_id(self.cluster))

    def geo_replication_show_site(self, site_uid):
        url = "{}/sites/{}".format(self.base_url, site_uid)
        return self.client.get(url)

    def geo_replication_show_self(self):
        url = "{}/self-site/".format(self.base_url)
        return self.client.get(url)

    def geo_replication_list(self):
        url = "{}/sites/".format(self.base_url)
        return self._list(url)

    def get_replication_token(self):
        url = "{}/self-site-token/".format(self.base_url)
        return self.client.get(url)

    def get_replication_add_site(self, site_token):
        data = {
            'token': site_token
        }
        url = "{}/sites/".format(self.base_url)
        return self.client.post_async(url, json=data)

    def get_replication_delete_site(self, site_uid):
        url = "{}/sites/{}".format(self.base_url, site_uid)
        return self.client.delete_async(url)
