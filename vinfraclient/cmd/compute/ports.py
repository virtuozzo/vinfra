import argparse
from vinfraclient.cmd import base


class FixedIpList(argparse.Action):
    def __init__(self, option_strings, dest, inline=False, **kwargs):
        super(FixedIpList, self).__init__(option_strings, dest, **kwargs)
        self.inline = inline

    def __call__(self, parser, namespace, values, option_string=None):
        fixed_ips = getattr(namespace, self.dest, []) or []
        if self.inline:
            if '@' in values:
                ip_address, subnet = values.split('@', 1)
                fixed_ips.append({'ip_address': ip_address,
                                  'subnet_id': subnet})
            else:
                fixed_ips.append({'ip_address': values})
        else:
            if ',' in values or '=' in values:
                parts = values.split(',')
                fixed_ip = {}
                for part in parts:
                    if "=" in part:
                        k, v = part.split("=")
                        fixed_ip[k.replace('-', '_')] = v
                fixed_ips.append(fixed_ip)
            else:
                fixed_ips.append({'ip_address': values})
        setattr(namespace, self.dest, fixed_ips)

def _prepare_filter_fixed_ip(parsed_fixed_ip):
    parts = parsed_fixed_ip.split(',')
    spec = []
    for part in parts:
        if '=' in part:
            k, v = part.split('=')
            spec.append('{}={}'.format(k.replace('-', '_'), v))
        else:
            spec.append('ip_address={}'.format(part))
    return ','.join(spec)

def _add_port_options(parser):
    parser.add_argument(
        '--name',
        metavar='<name>',
        help='Name of the port',
    )
    parser.add_argument(
        '--network-id',
        metavar='<network_id>',
        required=True,
        help='Network ID',
    )
    parser.add_argument(
        '--description',
        metavar='<description>',
        help='Description of the port',
    )
    parser.add_argument(
        '--device-id',
        metavar='<device_id>',
        help='Port device',
    )
    parser.add_argument(
        '--mac-address',
        metavar='<mac_address>',
        help='MAC address of the port',
    )
    parser.add_argument(
        '--device-owner',
        metavar='<device_ownder>',
        help='Device owner of this port',
    )
    parser.add_argument(
        '--vnic-type',
        metavar='<vnic_type>',
        choices=['normal',
                 'direct',
                 'macvtap',
                 'baremetal',
                 'direct-physical',
                 'virtio-forwarder'],
        help='VNIC type for this port',
    )
    parser.add_argument(
        '--project',
        metavar='<project>',
        help='Ownders project (name or ID)',
    )
    parser.add_argument(
        '--host-id',
        metavar='<host_id>',
        help='Allocate port on host <host-id> (ID only)',
    )
    status_group = parser.add_mutually_exclusive_group()
    status_group.add_argument(
        '--enable',
        dest='enable',
        action='store_true',
        help='Enable port',
    )
    status_group.add_argument(
        '--disable',
        dest='disable',
        action='store_true',
        help='Disable port',
    )
    parser.add_argument(
        '--tag',
        metavar='<tag>',
        action='append',
        dest='tags',
        help='Tags to be added to the port.'
        'This option can be used multiple times',
    )
    parser.add_argument(
        '--fixed-ip',
        dest='fixed_ips',
        action=FixedIpList,
        metavar='<ip-address|ip-address=<ip_address>,subnet-id=<subnet_id>>',
        help='Desired IP address and/or subnet.'
        'This option can be used multiple times.',
    )

def _get_port_options(parsed_args):
    attrs = {}
    if parsed_args.name:
        attrs['name'] = parsed_args.name
    if parsed_args.description:
        attrs['description'] = parsed_args.description
    if parsed_args.device_id:
        attrs['device_id'] = parsed_args.device_id
    if parsed_args.mac_address:
        attrs['mac_address'] = parsed_args.mac_address
    if parsed_args.device_owner:
        attrs['device_owner'] = parsed_args.device_owner
    if parsed_args.vnic_type:
        attrs['binding:vnic_type'] = parsed_args.vnic_type
    if parsed_args.project:
        attrs['project_id'] = parsed_args.project
    if parsed_args.host_id:
        attrs['binding:host_id'] = parsed_args.host_id
    if parsed_args.network_id:
        attrs['network_id'] = parsed_args.network_id
    if parsed_args.tags:
        attrs['tags'] = parsed_args.tags
    if parsed_args.enable:
        attrs['admin_state_up'] = True
    if parsed_args.disable:
        attrs['admin_state_up'] = False
    if parsed_args.fixed_ips:
        attrs['fixed_ips'] = parsed_args.fixed_ips

    return attrs

class ListPorts(base.Lister):
    _description = "List ports"
    _default_fields = ['id', 'status', 'network_id', 'mac_address', 'fixed_ips']
    _sort_keys = ['id', 'name', 'status', 'admin_state_up', 'device_ownder',
                  'created_at', 'updated_at']

    def configure_parser(self, parser):
        parser.add_argument(
            '--limit',
            metavar='<limit>',
            type=int,
            help='The maximum number of ports to list. To list all ports, '
                 'set the option to -1.'
        )
        parser.add_argument(
            '--marker',
            metavar='<id>',
            help='List ports after the marker.'
        )
        parser.add_argument(
            '--name',
            metavar='<name>',
            action='filter',
            operators='in',
            help='List ports according to their name',
        )
        parser.add_argument(
            '--device-owner',
            metavar='<device_owner>',
            action='filter',
            operators='in',
            help='List only ports with the specified device owner',
        )
        parser.add_argument(
            '--device-id',
            metavar='<device_id>',
            action='filter',
            operators='in',
            help='List only ports with the specified device ID',
        )
        parser.add_argument(
            '--network-id',
            metavar='<network>',
            action='filter',
            operators='in',
            help='List only ports connected to this network ID',
        )
        parser.add_argument(
            '--host-id',
            metavar='<host_id>',
            action='filter',
            operators='in',
            help='List only ports bound to this host ID',
        )
        parser.add_argument(
            '--project-id',
            metavar='<project_id>',
            action='filter',
            operators='in',
            help='List ports according to their project ID'
        )
        parser.add_argument(
            '--mac-address',
            metavar='<mac_address>',
            action='filter',
            operators='in',
            help='List only ports with this MAC address',
        )
        parser.add_argument(
            '--tags',
            metavar='<tag>[,<tag>,...]',
            action='filter',
            operators='in',
            help='List ports which have all given tag(s) '
            '(Comma-separated list of tags)',
        )
        parser.add_argument(
            '--fixed-ip',
            dest='fixed_ips',
            action='filter',
            operators='in',
            metavar='<ip-address|ip-address=<ip_address>,subnet-id=<subnet_id>>',
            help='List only ports with specific IP address and/or subnet.'
        )
        parser.add_argument(
            '--sort',
            metavar='<sort>',
            help="List ports sorted by key.\n"
                 "The sorting format is <sort-key>:<order>. The order is 'asc' or 'desc'.\n"
                 "Supported sort keys: {}".format(', '.join(self._sort_keys))
        )

    def do_action(self, parsed_args):
        filters = {}
        if parsed_args.name:
            filters['name'] = parsed_args.name
        if parsed_args.device_owner:
            filters['device_owner'] = parsed_args.device_owner
        if parsed_args.device_id:
            filters['device_id'] = parsed_args.device_id
        if parsed_args.host_id:
            filters['binding:host_id'] = parsed_args.host_id
        if parsed_args.network_id:
            filters['network_id'] = parsed_args.network_id
        if parsed_args.mac_address:
            filters['mac_address'] = parsed_args.mac_address
        if parsed_args.project_id:
            filters['project_id'] = parsed_args.project_id
        if parsed_args.tags:
            filters['tags'] = parsed_args.tags.split(',')
        if parsed_args.fixed_ips:
            filters['fixed_ips'] = _prepare_filter_fixed_ip(parsed_args.fixed_ips)
        if parsed_args.sort:
            filters['sort'] = parsed_args.sort

        return self.app.vinfra.compute.ports.list(limit=parsed_args.limit,
                                                  marker=parsed_args.marker,
                                                  filters=filters)

class ShowPort(base.ShowOne):
    _description = "Show port details"

    def configure_parser(self, parser):
        parser.add_argument(
            'port',
            metavar='<port>',
            help='Port to display (ID)',
        )

    def do_action(self, parsed_args):
        return self.app.vinfra.compute.ports.show(parsed_args.port)

class DeletePort(base.ShowOne):
    _description = "Delete a port"

    def configure_parser(self, parser):
        parser.add_argument(
            'port',
            metavar='<port>',
            help='Port to delete (ID)',
        )

    def do_action(self, parsed_args):
        return self.app.vinfra.compute.ports.delete(parsed_args.port)

class CreatePort(base.ShowOne):
    _description = "Create a port"

    def configure_parser(self, parser):
        _add_port_options(parser)

    def do_action(self, parsed_args):
        attrs = _get_port_options(parsed_args)

        return self.app.vinfra.compute.ports.create(**attrs)

class UpdatePort(base.ShowOne):
    _description = "Set port properties"

    def configure_parser(self, parser):
        parser.add_argument(
            'port',
            metavar='<port>',
            help='Port to update (ID)',
        )
        _add_port_options(parser)

    def do_action(self, parsed_args):
        attrs = _get_port_options(parsed_args)

        return self.app.vinfra.compute.ports.update(parsed_args.port, **attrs)
