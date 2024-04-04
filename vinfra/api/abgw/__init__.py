import json
import sys

from vinfra import exceptions
from vinfra.api_versions import version_wrap
from vinfra.api import base, failure_domains
from vinfra.api.compute.storage_policies import get_api_redundancy
from vinfra.utils import flatten_args

from vinfra.api.abgw.georeplication import GeoReplication
from vinfra.api.abgw.registrations import AbgwRegistrationsApi


# pylint: disable=function-redefined
class AbgwApi(base.VinfraApi):

    def __init__(self, cluster):
        self.cluster = cluster
        self.base_url = "/{}/abgw".format(base.get_id(self.cluster))
        super(AbgwApi, self).__init__(cluster.manager.api)
        self.storage_params = StorageParams(self.cluster)
        self.volume_params = VolumeParams(self.cluster)
        self.geo_replication = GeoReplication(self.cluster)
        self.registrations = AbgwRegistrationsApi(self.cluster)
        self.sysinfo_conf = SysinfoConf(self.cluster)
        self.limits_params = ClientLimits(self.cluster)
        self.throttling_limits = ThrottlingLimits(self.cluster)

    def _adjust_nodes(self, nodes):
        abgw_private = 'Backup (ABGW) private'
        network_id_with_abgw_private = None

        for network in self.api.networks.list():
            if abgw_private in network.traffic_types:
                network_id_with_abgw_private = network.id
                break
        else:
            msg = (
                "Networks with the following required traffic types "
                "not found: {!r}".format(abgw_private)
            )
            raise exceptions.VinfraError(msg)
        nodes_data = []
        errors = list()
        for node in nodes:
            for iface in node.ifaces_manager.list():
                if iface.network == network_id_with_abgw_private:
                    nodes_data.append({
                        'node_id': base.get_id(node),
                        'private_iface': iface.name
                    })
                    break
            else:
                errors.append(
                    "Traffic type {!r} is not assigned on node {!r}".format(
                        abgw_private, node['host']
                    ))
        if errors:
            raise exceptions.VinfraError("\n".join(errors))
        return nodes_data

    @version_wrap("2.0", "5.0.1")
    def assign_nodes(self, nodes):
        nodes = self._adjust_nodes(nodes)
        url = "{}/assign".format(self.base_url)
        data = {"nodes": nodes}
        return self.client.post_async(url, json=data)

    @version_wrap("5.1.0")
    def assign_nodes(self, nodes):
        nodes = self._adjust_nodes(nodes)
        url = "{}/nodes/join/".format(self.base_url)
        data = {"nodes": nodes}
        return self.client.post_async(url, json=data)

    @version_wrap("2.0", "5.0.1")
    def get_nodes(self):
        return self.client.get(url="{}/nodes/".format(self.base_url))

    @version_wrap("5.1.0")
    def get_nodes(self):
        return self.get()['hosts']

    @version_wrap("2.0", "5.0.1")
    def create_async(
            self, nodes, domain,
            reg_server, reg_account, reg_password,
            tier, failure_domain, redundancy,
            storage_type, storage_params=None,
    ):
        nodes = self._adjust_nodes(nodes)
        redundancy = get_api_redundancy(redundancy)

        data = flatten_args(
            nodes=nodes,
            domain=domain,
            reg_server=reg_server,
            reg_account=reg_account,
            reg_password=reg_password,
            storage_type=storage_type,
            storage_params=storage_params,
            tier=tier,
            failure_domain=failure_domain,
            redundancy=redundancy,
        )
        if "storage_params" in data:
            self.storage_params.verify(
                nodes=nodes, storage_params=storage_params,
                storage_type=storage_type
            )
        url = "{}/register/".format(self.base_url)
        return self.client.post_async(url, json=data, log=False)

    @version_wrap("5.1.0")
    def create_async(
            self, nodes, name, address,
            account_server, username, password,
            tier, failure_domain, redundancy,
            storage_type, storage_params=None, location=None
    ):
        nodes = self._adjust_nodes(nodes)
        redundancy = get_api_redundancy(redundancy)

        registration_info = flatten_args(
            name=name,
            address=address,
            account_server=account_server,
            location=location,
            username=username,
            password=password,
        )

        data = flatten_args(
            nodes=nodes,
            storage_type=storage_type,
            storage_params=storage_params,
            tier=tier,
            failure_domain=failure_domain,
            redundancy=redundancy,
            registration=registration_info or None,
            **registration_info
        )
        if "storage_params" in data:
            self.storage_params.verify(
                nodes=nodes, storage_params=storage_params,
                storage_type=storage_type
            )
        url = "{}/deploy-standalone/".format(self.base_url)
        return self.client.post_async(url, json=data, log=False)

    def deploy_reverse_proxy_async(
            self, nodes, upstream_info_file,
            tier, failure_domain, redundancy,
            storage_type, storage_params=None, nameservers=None
    ):
        nodes = self._adjust_nodes(nodes)
        redundancy = get_api_redundancy(redundancy)

        data = flatten_args(
            nodes=nodes,
            storage_type=storage_type,
            storage_params=storage_params,
            tier=tier,
            failure_domain=failure_domain,
            redundancy=redundancy,
            nameservers=nameservers,
        )
        if "storage_params" in data:
            self.storage_params.verify(
                nodes=nodes, storage_params=storage_params,
                storage_type=storage_type
            )
        url = "{}/deploy-reverse-proxy/".format(self.base_url)
        files = {'json': (None, json.dumps(data), 'application/json'),
                 'upstream-info': upstream_info_file}

        resp = self.client.post(url, files=files)

        if nameservers:
            _show_hint(_extract_upstream_address(upstream_info_file), nameservers)

        return _BackupGatewayTask(self, resp)

    def turn_into_upstream_async(self):
        url = "{}/reverse-proxying/turn-into-upstream/".format(self.base_url)
        resp = self.client.post(url)
        return _BackupGatewayTask(self, resp)

    def deploy_upstream_async(
            self, nodes,
            tier, failure_domain, redundancy,
            storage_type, storage_params=None
    ):
        nodes = self._adjust_nodes(nodes)
        redundancy = get_api_redundancy(redundancy)

        data = flatten_args(
            nodes=nodes,

            storage_type=storage_type,
            storage_params=storage_params,
            tier=tier,
            failure_domain=failure_domain,
            redundancy=redundancy,
        )
        if "storage_params" in data:
            self.storage_params.verify(
                nodes=nodes, storage_params=storage_params,
                storage_type=storage_type
            )
        url = "{}/deploy-upstream/".format(self.base_url)
        resp = self.client.post(url, json=data)
        return _BackupGatewayTask(self, resp)

    def export_upstream(self, fdst):
        upstream_info_stream = self.client.send_request_raw(
            method="get",
            url="{}/reverse-proxying/export-upstream/".format(self.base_url),
            stream=True
        )

        for chunk in upstream_info_stream:
            fdst.write(chunk)

    def add_new_upstream_async(self, upstream_info_file, nameservers=None):
        data = {}
        if nameservers:
            data['nameservers'] = nameservers

        url = "{}/reverse-proxy/upstreams/".format(self.base_url)
        files = {'json': (None, json.dumps(data), 'application/json'),
                 'upstream-info': upstream_info_file}

        resp = self.client.post(url, files=files)

        if nameservers:
            _show_hint(_extract_upstream_address(upstream_info_file), nameservers)

        return _BackupGatewayTask(self, resp)

    def rebalance_upstream_async(self, upstreams_set, upstreams_exclude,
                                 registration_id, threshold):
        data = flatten_args(
            upstreams_set=[upstream.to_dict() for upstream in upstreams_set] \
                if upstreams_set else None,
            upstreams_exclude=upstreams_exclude,
            registration_id=registration_id,
            threshold=threshold)
        resp = self.client.post(
            url="{}/reverse-proxy/upstreams/rebalance/".format(self.base_url),
            json=data
        )
        return _BackupGatewayTask(self, resp)

    def import_accounts_async(self, source_upstream_id, accounts, log_dir):
        files = {
            'json': (None,
                     json.dumps(flatten_args(source_upstream_id=source_upstream_id,
                                             log_dir=log_dir)),
                     'application/json'),
            'accounts': accounts,
        }
        resp = self.client.post(
            "{}/reverse-proxy/import-accounts/".format(self.base_url),
            files=files,
        )
        return _BackupGatewayTask(self, resp)

    def move_accounts_async(self, source_upstream_id, target_upstream_id, accounts, log_dir):
        files = {
            'json': (None,
                     json.dumps(flatten_args(source_upstream_id=source_upstream_id,
                                             target_upstream_id=target_upstream_id,
                                             log_dir=log_dir)),
                     'application/json'),
            'accounts': accounts,
        }
        resp = self.client.post(
            "{}/reverse-proxy/move-accounts/".format(self.base_url),
            files=files,
        )
        return _BackupGatewayTask(self, resp)


    def remove_upstream_async(self, dc_uid):
        resp = self.client.delete(
            url="{}/reverse-proxy/upstreams/{}/".format(self.base_url, dc_uid),
        )
        return _BackupGatewayTask(self, resp)

    def retry(self, process_id=None):
        id_string = ('/' + process_id + '/') if process_id else '/'
        url = "{}/process{}retry/".format(self.base_url, id_string)
        return self.client.post(url)

    def cancel(self, process_id=None):
        id_string = ('/' + process_id + '/') if process_id else '/'
        url = "{}/process{}cancel/".format(self.base_url, id_string)
        return self.client.post(url)

    def show_process(self, process_id=None):
        id_string = ('/' + process_id + '/') if process_id else '/'
        url = "{}/process{}".format(self.base_url, id_string)
        return self.client.get(url)

    @version_wrap("2.0.0", "5.0.1")
    def get(self):
        url = "{}/register/".format(self.base_url)
        return self.client.get(url)

    @version_wrap("5.1.0")
    def get(self):
        url = "{}/deployment-info/".format(self.base_url)
        return self.client.get(url)

    @version_wrap("2.0.0", "5.0.1")
    def release_nodes(self, nodes):
        url = "{}/release/".format(self.base_url)
        data = {"nodes": nodes}
        return self.client.post_async(url, json=data)

    @version_wrap("5.1.0")
    def release_nodes(self, nodes):
        url = "{}/nodes/leave/".format(self.base_url)
        data = {"nodes": nodes}
        return self.client.post_async(url, json=data)

    @version_wrap("2.0.0", "5.0.1")
    def release(self, reg_account, reg_password, force=None):
        url = "{}/release/".format(self.base_url)
        nodes = [_['id'] for _ in self.get_nodes()]
        data = {
            "nodes": nodes,
            "reg_account": reg_account, "reg_password": reg_password,
        }
        if force is not None:
            data["force"] = force
        return self.client.post_async(url, json=data, log=False)

    @version_wrap("5.1.0")
    def release(self):
        url = "{}/nodes/leave/".format(self.base_url)
        nodes = [_['id'] for _ in self.get_nodes()]
        data = {"nodes": nodes}
        return self.client.post_async(url, json=data)

    @version_wrap("2.0.0", "5.0.1")
    def renew_certificates(self, reg_server, reg_account, reg_password):
        url = "{}/register/".format(self.base_url)
        data = {
            "reg_account": reg_account, "reg_password": reg_password,
            "reg_server": reg_server
        }
        return self.client.put_async(url, json=data, log=False)

    def restart(self):
        url = "{}/restart/".format(self.base_url)
        return self.client.post(url)


class VolumeParams(base.VinfraApi):

    def __init__(self, cluster):
        self.cluster = cluster
        self.base_url = "/{}/abgw/volume-params".format(
            base.get_id(self.cluster))
        super(VolumeParams, self).__init__(cluster.manager.api)

    def get(self):
        with failure_domains.api_version(self.client):
            return self.client.get(self.base_url)

    def change(self, redundancy, failure_domain, tier):
        data = {
            "redundancy": redundancy.to_api_dict(),
            "failure_domain": failure_domain,
            "tier": tier,
        }
        return self.client.put_async(self.base_url, json=data)


class StorageParams(base.VinfraApi):

    def __init__(self, cluster):
        self.cluster = cluster
        self.base_url = "/{}/abgw/storage-params".format(
            base.get_id(self.cluster))
        super(StorageParams, self).__init__(cluster.manager.api)

    def get(self):
        return self.client.get(self.base_url)

    def change(self, storage_type, storage_params):
        return self.client.put(
            self.base_url, json={
                'storage_params': storage_params,
                'storage_type': storage_type
            }
        )

    def verify(self, nodes, storage_type, storage_params):
        return self.client.post(
            url="{}/verify/".format(self.base_url),
            json={
                "nodes": nodes,
                "storage_params": storage_params,
                "storage_type": storage_type
            }
        )


class _BackupGatewayTask(base.PollTask):
    def __init__(self, api, resp):
        super(_BackupGatewayTask, self).__init__()
        self.api = api
        self.resp = resp

    def poll(self):
        process = self.get_info()
        if process is None:
            task = self.api.api.tasks.get(self.resp['task_id'])
            if task.state in ['success']:
                return {}

            elif task.state in ['aborted', 'cancelled', 'failed']:
                raise exceptions.VinfraError(
                    task.details or 'Task completed in {} state'.format(
                        task.state))

            return None

        elif process.get('finished') or process.get('failed'):
            return process

        return None

    def get_info(self):
        url = "{}/process/{}".format(self.api.base_url, self.resp.get('task_id', ''))
        return self.api.client.get(url)


class SysinfoConf(base.VinfraApi):

    def __init__(self, cluster):
        self.cluster = cluster
        self.base_url = "/{}/abgw/sysinfo-log".format(
            base.get_id(self.cluster))
        super(SysinfoConf, self).__init__(cluster.manager.api)

    def get(self):
        return self.client.get(self.base_url)

    def delete(self):
        return self.client.delete_async(self.base_url)

    def create(
            self,
            path=None,
            max_file_size=None,
            max_total_size=None,
            max_age=None
    ):
        data = {}
        if path is not None:
            data['path'] = path
        if max_file_size is not None:
            data['max_file_size'] = max_file_size
        if max_total_size is not None:
            data['max_total_size'] = max_total_size
        if max_age is not None:
            data['max_age'] = max_age
        return self.client.post_async(self.base_url, json=data)

    def update(
            self,
            path=None,
            max_file_size=None,
            max_total_size=None,
            max_age=None
    ):
        data = {}
        if path is not None:
            data['path'] = path
        if max_file_size is not None:
            data['max_file_size'] = max_file_size
        if max_total_size is not None:
            data['max_total_size'] = max_total_size
        if max_age is not None:
            data['max_age'] = max_age
        return self.client.put_async(self.base_url, json=data)


class ClientLimits(base.VinfraApi):

    def __init__(self, cluster):
        self.cluster = cluster
        self.base_url = "/{}/abgw/limits-params/".format(
            base.get_id(self.cluster))
        super(ClientLimits, self).__init__(cluster.manager.api)

    def get(self):
        return self.client.get(self.base_url)

    def update(
            self,
            max_connections=None,
            max_ingress=None,
            max_egress=None,
            apply_on_all_nodes=False
    ):
        data = {}
        if max_connections is not None:
            data['max_connections'] = max_connections
        if max_ingress is not None:
            data['max_ingress'] = max_ingress
        if max_egress is not None:
            data['max_egress'] = max_egress
        if apply_on_all_nodes:
            data['apply_on_all_nodes'] = apply_on_all_nodes

        return self.client.put_async(self.base_url, json=data)


class ThrottlingLimits(base.VinfraApi):

    def __init__(self, cluster):
        self.cluster = cluster
        self.base_url = "/{}/abgw/throttling-limits/".format(
            base.get_id(self.cluster))
        super(ThrottlingLimits, self).__init__(cluster.manager.api)

    def get(self):
        resp = self.client.get(self.base_url)
        if resp is None:
            return {"throttling": "Throttling is set to default"}
        return resp

    def delete(self):
        self.client.delete_async(self.base_url)
        return None

    def update(
            self,
            soft_threshold=None,
            s3_threshold=None
    ):
        data = {}
        if soft_threshold is not None:
            data['soft_threshold'] = soft_threshold
        if s3_threshold is not None:
            data['s3_threshold'] = s3_threshold

        return self.client.put_async(self.base_url, json=data)


def _extract_upstream_address(upstream_info_stream):
    upstream_info_stream.seek(0)
    try:
        parts = upstream_info_stream.read().split(b'\0')
        if len(parts) > 1:
            try:
                data = json.loads(parts[1])
            except Exception:
                return None

            address, _, _ = data['address'].partition(':')
            return address
    finally:  # pylint: disable=lost-exception
        upstream_info_stream.seek(0)

    return ''


def _show_hint(upstream_address, nameservers):
    default = 'xxxxxxxx-upstream.abgw-private.svc.vstoragedomain.'
    sys.stderr.write('''
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@ 1. Check if DNS traffic type is opened for {nameservers}.
@ 2. Run the following command on each HA node, and then make 
@ sure the address is resolvable, see `man dig`.
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[root@hostname ~]# cat <<EOF > /etc/coredns/zones/{address}.conf 
{address}.:53 {{
    log . {{
        class error
    }}
    cache 300s
    forward . {nameservers}
}}
EOF
[root@hostname ~]# systemctl reload coredns.service
[root@hostname ~]# dig +short {address}.
nodes.abgw-private.svc.vstoragedomain.
A.B.C.D

Or alternatively, you can obtain all IP addresses via dig
[root@hostname ~]# dig @{nameservers} +short {address}.
and add them to /etc/hosts


'''.format(address=upstream_address.rstrip('.') if upstream_address else default,
           nameservers=' '.join(nameservers)))
