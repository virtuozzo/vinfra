import argparse
import base64
import getpass
import os
import re
import sys

from vinfra import api_versions
from vinfra.api.compute.storage_policies import get_vinfra_redundancy
from vinfra.utils import first, flatten_args

from vinfraclient import exceptions
from vinfraclient.argtypes import boolean, parse_list_options
from vinfraclient.cmd.base import TaskCommand, ShowOne, Lister, Command
from vinfraclient.cmd.compute.storage_policy import storage_policy_options
from vinfraclient.utils import find_resource, get_cluster, get_stream


os_environ_reg_password_name = "BACKUP_REG_PASSWORD"


def ensure_abgw_exists(cluster):
    if cluster.abgw.get() is None:
        raise exceptions.CommandError(
            "This action can only be performed on a "
            "cluster with the backup service."
        )


def file_to_b64encode(file_path):
    if not os.path.exists(file_path):
        msg = "Path does not exist: "
        if file_path and len(file_path) > 255:
            msg += file_path[:255] + '...'
        else:
            msg += file_path
        raise argparse.ArgumentTypeError(msg)
    try:
        with open(file_path, 'r') as file_obj:
            return base64.b64encode(file_obj.read())
    except Exception as err:
        raise argparse.ArgumentTypeError(
            'Failed to open "{}" ({}).'.format(file_path, err))


def get_storage_params(parsed_args):
    if not hasattr(parsed_args, 'storage_params'):
        return None
    spp_dict = {
        spp.type: spp.args_tuple for spp in storage_params_parsers}
    available_params = list(spp_dict[parsed_args.storage_type])
    current_storage_params = parsed_args.storage_params or {}
    if [
            x for x in current_storage_params
            if not x.startswith(parsed_args.storage_type)
    ]:
        raise exceptions.CommandError(
            "Unexpected params was send for {!r} storage type.".format(
                parsed_args.storage_type
            )
        )
    not_found_required = list()
    storage_params = dict()
    template = re.compile("^{}_(.+)".format(parsed_args.storage_type))
    for storage_param_key, value in current_storage_params.items():
        (tmpl_res,) = template.search(storage_param_key).groups()
        storage_params[tmpl_res.replace("-", "_")] = value

    for available_param_name, available_param_kwargs in \
            available_params:
        if available_param_kwargs.get("required", False) and \
                available_param_name.replace("-", "_") not in storage_params:
            not_found_required.append(available_param_name)

    if not_found_required:
        raise exceptions.CommandError(
            "Next required params not found in command line: {!r}".format([
                "--{}-{}".format(
                    parsed_args.storage_type,
                    _.replace("_", "-")
                ) for _ in not_found_required
            ])
        )
    return storage_params


class StorageParamsAction(argparse.Action):
    def __init__(self, option_strings, dest, **kwargs):
        self._storage_params_key = dest
        super(StorageParamsAction, self).__init__(
            option_strings, 'storage_params', **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        storage_params = getattr(namespace, "storage_params") or {}
        storage_params.update({self._storage_params_key: values})
        setattr(namespace, "storage_params", storage_params)


class AbgwS3StorageParamsParser(object):
    type = 's3'
    args_tuple = (
        ('flavor', {
            "required": False,
            "choices": ["amazon", "alibaba", "authv2", "authv4"],
            "help": "Flavor name"
        }),
        ('region', {"required": False, "help": "Set region for Amazon S3"}),
        ('bucket', {"required": True, "help": "Bucket name"}),
        ('endpoint', {"required": True, "help": "Endpoint URL"}),
        ('access-key-id', {"required": True, "help": "Access Key ID"}),
        ('secret-key-id', {"required": True, "help": "Secret Key ID"}),
        ('cert-verify', {
            "type": boolean,
            "help": "Allow self-signed certificate of S3 endpoint"
        }),
    )
    help = "Create backup service on public S3 cloud."


class AbgwNfsStorageParamsParser(object):
    type = 'nfs'
    args_tuple = (
        ('host', {"required": True, "help": "NFS hostname or IP"}),
        ('export', {"required": True, "help": "Export name"}),
        ('version', {
            "required": True, "type": int,
            "choices": [3, 4], "help": "Nfs version"}),
    )
    help = "Create backup service on Network File System (NFS)."


class AbgwAzureStorageParamsParser(object):
    type = 'azure'
    args_tuple = (
        ('endpoint', {"required": True, "help": "Endpoint URL"}),
        ('container', {"required": True, "help": "Container"}),
        ('account-name', {"required": True, "help": "Account name"}),
        ('account-key', {"required": True, "help": "Account key"}),
    )
    help = "Create backup service on public Azure cloud."


class AbgwSwiftStorageParamsParser(object):
    type = 'swift'
    args_tuple = (
        ('auth-url', {
            "required": True, "help": "Authentication (keystone) URL"}),
        ('auth-version', {
            "required": False, "help": "Authentication protocol version"}),
        ('user-name', {"required": True, "help": "User name"}),
        ('api-key', {"required": True, "help": "API key (password)"}),
        ('domain', {"required": False, "help": "Domain name"}),
        ('domain-id', {"required": False, "help": "Domain ID"}),
        ('tenant', {"required": False, "help": "Tenant name"}),
        ('tenant-id', {"required": False, "help": "Tenant ID"}),
        ('tenant-domain', {"required": False, "help": "Tenant domain name"}),
        ('tenant-domain-id', {"required": False, "help": "Tenant domain ID"}),
        ('trust-id', {"required": False, "help": "Trust ID"}),
        ('region', {"required": False, "help": "Region name"}),
        ('internal', {"required": False, "help": "Internal parameter"}),
        ('container', {"required": False, "help": "Container"}),
        ('cert-verify', {
            "type": boolean,
            "help": "Allow self-signed certificate of Swift endpoint"
        }),
    )
    help = "Create backup service on public Swift cloud."


class AbgwGoogleStorageParamsParser(object):
    type = 'google'
    args_tuple = (
        ('bucket', {
            "required": True, "help": "Google bucket name"
        }),
        ('credentials', {
            "required": True, "type": file_to_b64encode,
            "help": "Path of google credentials file"
        }),
    )
    help = "Create backup service on public Google cloud."


class AbgwLocalStorageParamsParser(object):
    type = 'local'
    args_tuple = ()
    help = "Create backup service on this Acronis Cyber infrastructure cluster."


storage_params_parsers = (
    AbgwLocalStorageParamsParser,
    AbgwNfsStorageParamsParser,
    AbgwS3StorageParamsParser,
    AbgwSwiftStorageParamsParser,
    AbgwAzureStorageParamsParser,
    AbgwGoogleStorageParamsParser,
)


def adapt_parser_by_storage_params(parser):
    storage_type_choices = list()

    for storage_params_parser in storage_params_parsers:
        storage_type_choices.append(storage_params_parser.type)
        if not storage_params_parser.args_tuple:
            continue
        argument_group = parser.add_argument_group(
            title="Storage params for {!r} storage".format(
                storage_params_parser.type),
            description=storage_params_parser.help,
        )
        for args_tuple_name, args_tuple_kwargs in \
                storage_params_parser.args_tuple:
            help_ = args_tuple_kwargs.get("help", "")
            if args_tuple_kwargs.get("required", False):
                help_ += ". Required for {!r} storage type".format(
                    storage_params_parser.type)
            argument_group.add_argument(
                "--{}-{}".format(storage_params_parser.type, args_tuple_name),
                action=StorageParamsAction, help=help_,
                metavar="<{}>".format(args_tuple_name.upper()),
                **{
                    k: v for k, v in args_tuple_kwargs.items()
                    if k not in ("help", "required")
                }
            )
    return storage_type_choices


def get_reg_password(parsed_args):
    reg_password = os.environ.get(os_environ_reg_password_name)
    if parsed_args.stdin:
        reg_password = getpass.getpass("Password: ")
    elif not reg_password:
        raise exceptions.CommandError(
            "Registration password is required. "
            "Use --stdin for set password by command line, "
            "or set {} in environ.".format(
                os_environ_reg_password_name
            )
        )
    return reg_password


class CreateBackupService(TaskCommand):
    _description = "Create the backup cluster."

    def configure_parser(self, parser):
        parser.add_argument(
            "--nodes",
            metavar="<nodes>", type=parse_list_options, required=True,
            help="A comma-separated list of node hostnames or IDs"
        )
        # only encoding
        storage_policy_options(
            parser, required=False, use_defaults=False, replicas=False)

        storage_type_choices = adapt_parser_by_storage_params(parser)

        parser.add_argument(
            "--storage-type", dest="storage_type", required=True,
            choices=storage_type_choices, help="Choose storage type"
        )
        registration_group = parser.add_argument_group(
            title="Cloud registrations options",
        )
        registration_group.add_argument(
            "--name",
            metavar="<name>",
            help="Backup registration name."
        )
        registration_group.add_argument(
            "--address",
            metavar="<address>",
            help="Backup registration address."
        )
        registration_group.add_argument(
            "--location",
            metavar="<location>",
            help="Backup registration location."
        )
        registration_group.add_argument(
            "--username",
            metavar="<username>",
            dest='username',
            help=(
                "Partner account in the cloud or of an organization "
                "administrator on the local management server."
            )
        )
        registration_group.add_argument(
            "--account-server",
            metavar="<account-server>",
            dest='account_server',
            help=(
                "URL of the cloud management portal or the hostname/IP "
                "address and port of the local management server."
            )
        )
        registration_group.add_argument(
            "--stdin", action="store_true",
            help="Use for setting registration password from stdin"
        )

        # Deprecated arguments
        parser.add_argument(
            "--domain", metavar="<domain>", dest="address",
            help="Domain name for the backup cluster. (DEPRECATED)"
        )
        parser.add_argument(
            "--reg-account", metavar="<reg-account>", dest="username",
            help=(
                "Partner account in the cloud or of an organization "
                "administrator on the local management server. (DEPRECATED)"
            )
        )
        parser.add_argument(
            "--reg-server", metavar="<reg-server>", dest="account_server",
            help=(
                "URL of the cloud management portal or the hostname/IP "
                "address and port of the local management server. (DEPRECATED)"
            )
        )

    def do_action(self, parsed_args):
        if self._cmd_name == 'service backup cluster create':
            self.app.stderr.write(
                "The command '{}' is deprecated and will be removed in the "
                "future. Please use 'service backup cluster deploy-standalone' "
                "command.\n".format(self._cmd_name))


        cluster = get_cluster(self.app.vinfra)
        nodes = [find_resource(self.app.vinfra.nodes, node)
                 for node in parsed_args.nodes]
        if self.app.vinfra.api_version < api_versions.HCI_VER_51:
            create_params = dict(
                nodes=nodes,
                domain=parsed_args.address,
                reg_account=parsed_args.username,
                reg_server=parsed_args.account_server,
                reg_password=get_reg_password(parsed_args),
                tier=parsed_args.tier,
                redundancy=parsed_args.redundancy,
                failure_domain=parsed_args.failure_domain,
                storage_type=parsed_args.storage_type,
            )
        else:
            has_reg = flatten_args(
                address=parsed_args.address,
                location=parsed_args.location,
                username=parsed_args.username,
                account_server=parsed_args.account_server,
            )
            create_params = dict(
                nodes=nodes,
                name=parsed_args.name,
                address=parsed_args.address,
                location=parsed_args.location,
                username=parsed_args.username,
                account_server=parsed_args.account_server,
                password=get_reg_password(parsed_args) if has_reg else None,
                tier=parsed_args.tier,
                redundancy=parsed_args.redundancy,
                failure_domain=parsed_args.failure_domain,
                storage_type=parsed_args.storage_type,
            )
        storage_params = get_storage_params(parsed_args)
        if storage_params:
            create_params.update({"storage_params": storage_params})
        return cluster.abgw.create_async(**create_params)


class TurnIntoUpstreamBackupGateway(TaskCommand):
    _description = "Turn the existing Standalone Backup Gateway into Upstream."

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        return cluster.abgw.turn_into_upstream_async()


class DeployUpstreamBackupGateway(TaskCommand):
    _description = "Create Upstream Backup Gateway for Reverse Proxy."

    def configure_parser(self, parser):
        parser.add_argument(
            "--nodes",
            metavar="<nodes>", type=parse_list_options, required=True,
            help="A comma-separated list of node hostnames or IDs"
        )
        # only encoding
        storage_policy_options(
            parser, required=False, use_defaults=False, replicas=False)

        storage_type_choices = adapt_parser_by_storage_params(parser)

        parser.add_argument(
            "--storage-type", dest="storage_type", required=True,
            choices=storage_type_choices, help="Choose storage type"
        )

    def do_action(self, parsed_args):

        cluster = get_cluster(self.app.vinfra)
        nodes = [find_resource(self.app.vinfra.nodes, node)
                 for node in parsed_args.nodes]

        create_params = dict(
            nodes=nodes,
            tier=parsed_args.tier,
            redundancy=parsed_args.redundancy,
            failure_domain=parsed_args.failure_domain,
            storage_type=parsed_args.storage_type,
        )
        storage_params = get_storage_params(parsed_args)
        if storage_params:
            create_params.update({"storage_params": storage_params})
        return cluster.abgw.deploy_upstream_async(**create_params)


class RenewBackupCertificates(TaskCommand):
    _description = "Update certificates for the backup cluster."

    def configure_parser(self, parser):
        parser.add_argument(
            "--reg-account", required=True,
            help=(
                "Partner account in the cloud or of an organization "
                "administrator on the local management server."
            )
        )
        parser.add_argument(
            "--reg-server", required=True,
            help=(
                "URL of the cloud management portal or the hostname/IP "
                "address and port of the local management server."
            )
        )
        parser.add_argument(
            "--server-cert-only",
            action="store_true",
            help="Update server certificate only."
        )
        parser.add_argument(
            "--stdin", action="store_true",
            help="Use for setting registration password from stdin."
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        if self.app.vinfra.api_version < api_versions.HCI_VER_51:
            return cluster.abgw.renew_certificates(
                reg_server=parsed_args.reg_server,
                reg_account=parsed_args.reg_account,
                reg_password=get_reg_password(parsed_args)
            )
        else:
            registrations = cluster.abgw.registrations.list()
            if len(registrations) != 1:
                raise exceptions.VinfraError(
                    "Unable to update certificates due to multiple registrations. "
                    "Please use 'service backup registration renew-certificates' command."
                )
            registration = first(registrations)
            return cluster.abgw.registrations.renew_certificates(
                registration,
                server_cert_only=parsed_args.server_cert_only,
                username=parsed_args.reg_account,
                password=get_reg_password(parsed_args),
            )


class ExportUpstream(ShowOne):
    _description = (
        "Export upstream Backup Gateway info."
    )

    def configure_parser(self, parser):
        parser.add_argument(
            "--output-file",
            dest="output_file",
            metavar="<output-filepath>",
            help=(
                "Path where the upstream info file will be exported."
            )
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)

        fdst = None
        close_fd = None
        if parsed_args.output_file:
            if os.path.exists(parsed_args.output_file):
                raise exceptions.ValidationError(
                    "Path already exists. Provide another path or the "
                    "existing file will be overwritten."
                )
            if os.path.isdir(parsed_args.output_file):
                raise exceptions.ValidationError(
                    "The provided path is a directory. "
                    "Specify a file to download."
                )

            output_dir = os.path.dirname(parsed_args.output_file)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            fdst = open(parsed_args.output_file, 'wb')
            close_fd = fdst
        else:
            fdst = sys.stdout.buffer  # pylint: disable=no-member

        cluster.abgw.export_upstream(fdst)

        if close_fd:
            close_fd.close()


class DeployReverseProxyBackupGateway(TaskCommand):
    _description = "Create Reverse Proxy Backup Gateway."

    def configure_parser(self, parser):
        parser.add_argument(
            "--nodes",
            metavar="<nodes>", type=parse_list_options, required=True,
            help="A comma-separated list of node hostnames or IDs"
        )
        # only encoding
        storage_policy_options(
            parser, required=False, use_defaults=False, replicas=False)

        storage_type_choices = adapt_parser_by_storage_params(parser)

        parser.add_argument(
            "--storage-type", dest="storage_type", required=True,
            choices=storage_type_choices, help="Choose storage type"
        )
        parser.add_argument(
            "--upstream-info-file", dest="upstream_info_file",
            required=True, help="Upstream info file path."
        )
        parser.add_argument(
            "--nameserver", action='append', dest="nameservers", required=False,
            help="Nameserver IP address. This DNS server will serve "
                 "recursive queries from Reverse-proxy."
        )

    def do_action(self, parsed_args):

        cluster = get_cluster(self.app.vinfra)
        nodes = [find_resource(self.app.vinfra.nodes, node)
                 for node in parsed_args.nodes]

        create_params = dict(
            nodes=nodes,
            tier=parsed_args.tier,
            redundancy=parsed_args.redundancy,
            failure_domain=parsed_args.failure_domain,
            storage_type=parsed_args.storage_type,
            upstream_info_file=get_stream(parsed_args.upstream_info_file),
            nameservers=parsed_args.nameservers,
        )
        storage_params = get_storage_params(parsed_args)
        if storage_params:
            create_params.update({"storage_params": storage_params})
        return cluster.abgw.deploy_reverse_proxy_async(**create_params)


class AddNewUpstream(TaskCommand):
    _description = "Add new upstream to Reverse Proxy Backup Gateway."

    def configure_parser(self, parser):
        parser.add_argument(
            "--upstream-info-file", dest="upstream_info_file",
            required=True, help="Upstream info file path."
        )
        parser.add_argument(
            "--nameserver", action='append', dest="nameservers", required=False,
            help=argparse.SUPPRESS  # Upstream cluster as a nameserver.
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        return cluster.abgw.add_new_upstream_async(
            upstream_info_file=get_stream(parsed_args.upstream_info_file),
            nameservers=parsed_args.nameservers)


class UpstreamWeight(object):
    metavar = "<dc_uid>:<weight>"
    help = ("Upstream weight in the format:\n"
            "dc_uid: Datacenter UID of upstream Backup Gateway;\n"
            "weight: The weight of the specified upstream.\n"
            "(this option can be used multiple times).")

    def __init__(self, dc_uid, weight):
        self.dc_uid = dc_uid
        self.weight = weight

    def __str__(self):
        return "{}:{}".format(self.dc_uid, self.weight)

    __repr__ = __str__

    @classmethod
    def from_string(cls, value):
        if ':' not in value:
            raise argparse.ArgumentTypeError("unrecognized format mapping")

        dc_uid, weight = value.split(':')

        if not weight.isdigit():
            raise argparse.ArgumentTypeError(
                "Invalid 'weight': {!r}.".format(weight))

        return cls(dc_uid, int(weight))

    def to_dict(self):
        return {
            'dc_uid': self.dc_uid,
            'weight': self.weight,
        }


class Rebalance(TaskCommand):
    _description = "Rebalance upstream Backup Gateways."

    def configure_parser(self, parser):
        parser.add_argument(
            "--set",
            dest="upstreams_set",
            action="append",
            required=False,
            metavar=UpstreamWeight.metavar,
            type=UpstreamWeight.from_string,
            help=UpstreamWeight.help,
        )
        parser.add_argument(
            "--exclude",
            dest="upstreams_exclude",
            action="append",
            required=False,
            help="Datacenter UID of upstream Backup Gateway to exclude "
                 "(this option can be used multiple times).",
        )
        parser.add_argument(
            "--registration-id",
            dest="registration_id",
            required=False,
            help="Registration ID of upstream Backup Gateway "
                 "for per-registration rebalancing.",
        )
        parser.add_argument(
            "--threshold",
            dest="threshold",
            required=False,
            help="Free disk space threshold, in percent, to exclude upstream.",
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        return cluster.abgw.rebalance_upstream_async(
            parsed_args.upstreams_set, parsed_args.upstreams_exclude,
            parsed_args.registration_id, parsed_args.threshold)


class ImportAccounts(TaskCommand):
    _description = "Import accounts from upstream Backup Gateway to reverse proxy."

    def configure_parser(self, parser):
        parser.add_argument(
            "--source-upstream-id", dest="source_upstream_id",
            required=True, help="Datacenter UID of a source upstream Backup Gateway."
        )
        parser.add_argument(
            "--accounts-file", dest="accounts_file",
            required=True, help="Path to accounts file."
        )
        parser.add_argument(
            "--log-dir", dest="log_dir",
            required=False, help="Log directory."
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        return cluster.abgw.import_accounts_async(
            parsed_args.source_upstream_id,
            get_stream(parsed_args.accounts_file),
            parsed_args.log_dir,
        )


class MoveAccounts(TaskCommand):
    _description = "Move accounts from one upstream Backup Gateway to another."

    def configure_parser(self, parser):
        parser.add_argument(
            "--source-upstream-id", dest="source_upstream_id",
            required=True, help="Datacenter UID of a source upstream Backup Gateway."
        )
        parser.add_argument(
            "--target-upstream-id", dest="target_upstream_id",
            required=True, help="Datacenter UID of a target upstream Backup Gateway."
        )
        parser.add_argument(
            "--accounts-file", dest="accounts_file",
            required=True, help="Path to accounts file."
        )
        parser.add_argument(
            "--log-dir", dest="log_dir",
            required=False, help="Log directory."
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        return cluster.abgw.move_accounts_async(
            parsed_args.source_upstream_id,
            parsed_args.target_upstream_id,
            get_stream(parsed_args.accounts_file),
            parsed_args.log_dir,
        )


class RemoveUpstream(TaskCommand):
    _description = "Remove upstream from Reverse Proxy Backup Gateway."

    def configure_parser(self, parser):
        parser.add_argument(
            "--dc-uid", dest="dc_uid",
            required=True, help="Datacenter UUID of upstream Backup Gateway."
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        return cluster.abgw.remove_upstream_async(parsed_args.dc_uid)


class Process(ShowOne):
    _description = "Backup Gateway process inspection/manipulation."

    def configure_parser(self, parser):
        subcommands = parser.add_mutually_exclusive_group()
        subcommands.add_argument(
            "--show", action="store_true", required=False, default=False,
            help="Show state of the Backup Gateway process."
        )
        subcommands.add_argument(
            "--retry", action="store_true", required=False, default=False,
            help="Retry a suspended Backup Gateway process."
        )
        subcommands.add_argument(
            "--cancel", action="store_true", required=False, default=False,
            help="Try to cancel an active Backup Gateway process."
        )

        parser.add_argument(
            "--process-id", required=False, default=None,
            help="Backup Gateway process ID."
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        if parsed_args.show:
            return cluster.abgw.show_process(parsed_args.process_id)
        elif parsed_args.retry:
            return cluster.abgw.retry(parsed_args.process_id)
        elif parsed_args.cancel:
            return cluster.abgw.cancel(parsed_args.process_id)
        raise exceptions.VinfraError('No options')


class ReleaseBackupService(TaskCommand):
    _description = "Delete the backup cluster."

    def configure_parser(self, parser):
        parser.add_argument(
            "--reg-account", required=False,
            help=(
                "Partner account in the cloud or of an organization "
                "administrator on the local management server."
            )
        )
        parser.add_argument(
            "--force", action="store_true", required=False,
            default=False,
            help="Forcibly release the backup cluster"
        )
        parser.add_argument(
            "--stdin", action="store_true",
            help="Use for setting registration password from stdin"
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        kwargs = {}
        if self.app.vinfra.api_version < api_versions.HCI_VER_51:
            reg_password = None
            if not parsed_args.force and not parsed_args.reg_account:
                raise exceptions.ValidationError(
                    "Incorrect argument: --reg-account "
                    "required for releasing backup service without force."
                )
            elif not parsed_args.force:
                reg_password = get_reg_password(parsed_args)
            kwargs['force'] = parsed_args.force
            kwargs['reg_password'] = reg_password
            kwargs['reg_account'] = parsed_args.reg_account
        ensure_abgw_exists(cluster)
        return cluster.abgw.release(**kwargs)


class ShowBackupService(ShowOne):
    _description = "Display backup cluster details."

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        rv = cluster.abgw.get()
        if rv:
            for upstream in rv.get('upstreams', []):
                if upstream.get('weight') == -1:
                    upstream.pop('weight')
        return rv


class AddNodes(TaskCommand):
    _description = "Add list of nodes to backup cluster."

    def configure_parser(self, parser):
        parser.add_argument(
            "--nodes",
            metavar="<nodes>", required=True, type=parse_list_options,
            help="A comma-separated list of node hostnames or IDs"
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        nodes = [
            find_resource(self.app.vinfra.nodes, node)
            for node in parsed_args.nodes
        ]
        return cluster.abgw.assign_nodes(nodes)


class ListNodes(Lister):
    _description = "List backup nodes."

    @property
    def _default_fields(self):
        default_fields = ['id', 'host', 'is_active']
        if self.app.vinfra.api_version >= api_versions.HCI_VER_51:
            default_fields.append('systemd')
        return default_fields

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        result = []
        for node in cluster.abgw.get_nodes():
            node_view = find_resource(self.app.vinfra.nodes, node['id'])
            node.update(node_view.to_dict())
            if self.app.vinfra.api_version >= api_versions.HCI_VER_51:
                node['is_active'] = node['systemd'] == 'active'
            result.append(node)
        return result


class ReleaseNode(TaskCommand):
    _description = "Release list of nodes from backup cluster."

    def configure_parser(self, parser):
        parser.add_argument(
            "--nodes",
            metavar="<nodes>", required=True, type=parse_list_options,
            help="A comma-separated list of node hostnames or IDs"
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        nodes = [
            find_resource(self.app.vinfra.nodes, node).id
            for node in parsed_args.nodes
        ]
        return cluster.abgw.release_nodes(nodes)


class ShowStorageParams(ShowOne):
    _description = "Display storage parameters."

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        return cluster.abgw.storage_params.get()


class ChangeStorageParams(Command):
    _description = "Modify storage parameters."

    def configure_parser(self, parser):
        storage_type_choices = adapt_parser_by_storage_params(parser)
        parser.add_argument(
            "--storage-type", dest="storage_type", required=True,
            choices=storage_type_choices, help="Choose storage type"
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        current_storage_params = cluster.abgw.storage_params.get()
        if (
                current_storage_params["storage_type"] !=
                parsed_args.storage_type
        ):
            raise exceptions.ValidationError(
                "Storage type cannot be changed.")
        storage_params = get_storage_params(parsed_args)
        return cluster.abgw.storage_params.change(
            storage_params=storage_params,
            storage_type=parsed_args.storage_type,
        )


class ShowVolumeParams(ShowOne):
    _description = "Display volume parameters."

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        return cluster.abgw.volume_params.get()


class ChangeVolumeParams(TaskCommand):
    _description = "Modify volume parameters."

    def configure_parser(self, parser):
        # only encoding
        storage_policy_options(
            parser, required=False, use_defaults=False, replicas=False)

    def do_action(self, parsed_args):
        if not any([
                parsed_args.redundancy, parsed_args.failure_domain,
                parsed_args.tier
        ]):
            raise exceptions.CommandError(
                "Arguments missing. "
                "Use --help for more information about the command."
            )

        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        current_volume_params = cluster.abgw.volume_params.get()
        return cluster.abgw.volume_params.change(
            redundancy=(
                parsed_args.redundancy or get_vinfra_redundancy(
                    current_volume_params['redundancy']
                )
            ),
            failure_domain=(
                parsed_args.failure_domain or
                current_volume_params['failure_domain']
            ),
            tier=parsed_args.tier or current_volume_params['tier'],
        )


class ShowSysinfoConfig(ShowOne):
    _description = "Show backup storage sysinfo configuration properties."

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        return cluster.abgw.sysinfo_conf.get()


class DisableSysinfoConfig(TaskCommand):
    _description = "Disable backup storage sysinfo configuration by deleting it."

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        return cluster.abgw.sysinfo_conf.delete()


class SysinfoConfig(TaskCommand):
    def configure_parser(self, parser):
        parser.add_argument(
            "--path", required=False, default=None,
            help=(
                "Path to log files. Valid path to the folder that will keep the logs. "
                "Example: '/var/log/abgw/sysinfo'"
            )
        )
        parser.add_argument(
            "--max-file-size", required=False, default=None,
            help=(
                "Max log file size. Valid option is an integer number without suffix (for bytes)"
                " or with k or K, m or M, g or G, t or T as suffix for KB, MB, GB,"
                " TB respectively. Example: '512M'"
            )
        )
        parser.add_argument(
            "--max-total-size", required=False, default=None,
            help=(
                "Max total size of all log files. Valid option is an integer without suffix "
                "(for bytes) or with k or K, m or M, g or G, t or T as suffix for"
                " KB, MB, GB, TB respectively. Example: '2G'"
            )
        )
        parser.add_argument(
            "--max-age", required=False, default=None,
            help=(
                "Max age/time to keep log files. Valid option is an integers with suffix "
                "s or S, m or M, h or H, d or D, w or W as suffix"
                " for seconds, minutes, hours, days, weeks respectively. "
                "Example: '4w'"
            )
        )


class EnableSysinfoConfig(SysinfoConfig):
    _description = "Enable backup storage sysinfo configuration by creating" \
                   " it with default values or provided ones."

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        return cluster.abgw.sysinfo_conf.create(
            parsed_args.path,
            parsed_args.max_file_size,
            parsed_args.max_total_size,
            parsed_args.max_age
        )


class UpdateSysinfoConfig(SysinfoConfig):
    _description = "Update backup storage sysinfo configuration with provided parameters."

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        return cluster.abgw.sysinfo_conf.update(
            parsed_args.path,
            parsed_args.max_file_size,
            parsed_args.max_total_size,
            parsed_args.max_age
        )


class ClientLimits(TaskCommand):
    def configure_parser(self, parser):
        parser.add_argument(
            "--max-connections", metavar="<max-connections>",
            help=(
                "The maximum number of TCP/IP connections the client can create "
                "during a single backup/restore session"
            )
        )
        parser.add_argument(
            "--max-ingress", metavar="<max-ingress>",
            help=(
                "The maximum speed, in bytes per second, the client can have "
                "for writing to the storage during a single backup/restore session"
            )
        )
        parser.add_argument(
            "--max-egress", metavar="<max-egress>",
            help=(
                "The maximum speed, in bytes per second, the client can have "
                "for reading from the storage during a single backup/restore session."
            )
        )
        parser.add_argument(
            "--apply-on-all-nodes",
            action="store_true",
            help="Apply the limits on all backup storage nodes."
        )


class ShowClientLimits(ShowOne):
    _description = "Show limits of the backup storage client."

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        return cluster.abgw.limits_params.get()


class ChangeLimitsParams(ClientLimits):
    _description = "Update limits of the backup storage client."

    def do_action(self, parsed_args):
        if not any([
                parsed_args.max_connections, parsed_args.max_ingress,
                parsed_args.max_egress
        ]):
            raise exceptions.CommandError(
                "Arguments missing. "
                "Use --help for more information about the command."
            )

        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        return cluster.abgw.limits_params.update(
            parsed_args.max_connections,
            parsed_args.max_ingress,
            parsed_args.max_egress,
            parsed_args.apply_on_all_nodes,
        )


class ShowThrottlingConfig(ShowOne):
    _description = "Show backup storage throttling configuration properties."

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        return cluster.abgw.throttling_limits.get()


class ResetThrottlingConfig(ShowOne):
    _description = "Reset backup storage custom throttling configuration by deleting it."

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        return cluster.abgw.throttling_limits.delete()


class ThrottlingConfig(TaskCommand):
    def configure_parser(self, parser):
        parser.add_argument(
            "--soft-threshold", required=False, default=None,
            help=(
                "Soft threshold limit in %%. "
                "Valid range is between 85-95%%"
            )
        )
        parser.add_argument(
            "--s3-threshold", required=False, default=None,
            help=(
                "Object storage threshold limit in MBs. "
                "Must be higher than the default limit of 300 MBs. "
                "This parameter can be used only if backup storage is object storage!"
            )
        )


class SetThrottlingConfig(ThrottlingConfig):
    _description = "Set backup storage throttling configuration with provided parameters."

    def do_action(self, parsed_args):
        if not any([
                parsed_args.soft_threshold, parsed_args.s3_threshold
        ]):
            raise exceptions.CommandError(
                "Arguments missing. "
                "Use --help for more information about the command."
            )

        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        return cluster.abgw.throttling_limits.update(
            parsed_args.soft_threshold,
            parsed_args.s3_threshold
        )


class RestartBackupNodes(ShowOne):
    _description = 'Restart backup nodes'

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        url = "{}/restart/".format(cluster.abgw.base_url)
        return cluster.abgw.client.post(url)


class ChangeUpstream(ShowOne):
    _description = 'Change upstream redirect address'

    def configure_parser(self, parser):
        parser.add_argument(
            "--upstream-id", dest="upstream_id", required=True,
            help="Datacenter UUID of upstream Backup Gateway."
        )
        group = parser.add_mutually_exclusive_group(required=False)
        group.add_argument(
            "--redirect-address", dest="redirect_address", help="Redirect address"
        )
        group.add_argument(
            "--no-redirect", dest="no_redirect", action='store_true', help="No redirect address"
        )

    def do_action(self, parsed_args):
        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        data = {}
        if parsed_args.no_redirect:
            data["redirect_address"] = None
        elif parsed_args.redirect_address:
            data["redirect_address"] = parsed_args.redirect_address
        return cluster.abgw.client.patch(
            "{}/reverse-proxy/upstreams/{}/".format(
                cluster.abgw.base_url, parsed_args.upstream_id), json=data)


class SetUpstreamOnly(ShowOne):
    _description = 'Enable/disable upstream only parameter'

    def configure_parser(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            "--enable", required=False, action='store_true', help="Set upstream_only mode")
        group.add_argument(
            "--disable", required=False, action='store_true', help="Unset upstream_only mode")

    def do_action(self, parsed_args):
        if parsed_args.enable:
            cmd = 'enable'
        elif parsed_args.disable:
            cmd = 'disable'
        else:
            raise NotImplementedError

        cluster = get_cluster(self.app.vinfra)
        ensure_abgw_exists(cluster)
        return cluster.abgw.client.post(
            "{}/upstream-only/{}/".format(cluster.abgw.base_url, cmd))
