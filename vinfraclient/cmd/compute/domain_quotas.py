import argparse
import collections
import logging

from vinfraclient import utils
from vinfraclient.cmd.base import ShowOne, Command

LOG = logging.getLogger(__name__)


class ShowComputeDomainQuotas(ShowOne):
    _description = "List compute domain quotas."
    _humanized_fields = (
        'storage.storage_policies.',
        'storage.volumes_backups',
        'compute.ram_quota.',
    )

    @classmethod
    def _flatten_dict(cls, dict_, parent_key=None):
        rv = []
        for k, v in dict_.items():
            if parent_key:
                new_key = "{}.{}".format(parent_key, k)
            else:
                new_key = k

            if isinstance(v, collections.MutableMapping):
                rv.extend(cls._flatten_dict(v, new_key).items())
            else:
                for field in cls._humanized_fields:
                    if new_key.startswith(field) and v > 0:
                        v = utils.SizeValue(v).humanize()
                rv.append((new_key, v))
        return dict(rv)

    def configure_parser(self, parser):
        parser.add_argument(
            "domain_id",
            help="Domain ID",
        )
        parser.add_argument(
            "--usage",
            action="store_true",
            help="Include quota usage",
        )

    @staticmethod
    def _safe_mul(val, mul):
        return val if val < 0 else int(val * mul)

    @staticmethod
    def _fixup_ram(data):
        compute = data.get('compute')
        if not compute:
            return

        # Starting from 3.5 release API returns ram in bytes.
        # But project 'ram' quotas is still reported 'ram' in MB,
        # and 'ram_quota' contains value in bytes.
        compute['ram_quota'] = compute.pop('ram')

    def do_action(self, parsed_args):
        data = self.app.vinfra.compute.domain_quotas.show(
            parsed_args.domain_id, usage=parsed_args.usage)
        data = data.to_dict()
        self._fixup_ram(data)

        if parsed_args.formatter == 'table':
            return self._flatten_dict(data)

        return data


class UpdateComputeDomainQuotas(Command):
    _description = "Update compute domain quotas."

    @staticmethod
    def storage_policy(value):
        try:
            sp_name, sp_size = value.strip().rsplit(':', 1)
            sp_size = utils.SizeValue(sp_size).value
        except ValueError:
            raise argparse.ArgumentTypeError(
                'Invalid --storage-policy format')
        return sp_name, sp_size

    @staticmethod
    def size_value(value):
        try:
            return utils.SizeValue(value.strip()).value
        except ValueError:
            raise argparse.ArgumentTypeError(
                'Invalid size value format')

    def configure_parser(self, parser):
        parser.add_argument(
            "domain_id",
            help="Domain ID"
        )
        parser.add_argument(
            "--cores",
            type=int,
            metavar='<cores>',
            help="Number of cores",
        )
        parser.add_argument(
            "--ram-size",
            type=self.size_value,
            metavar='<ram>',
            help="Amount of RAM",
        )
        parser.add_argument(
            "--storage-policy",
            dest="storage_policies",
            action="append",
            type=self.storage_policy,
            help="Storage policy in the format <storage_policy>:<size>. "
                 "(this option can be used multiple times).",
        )
        parser.add_argument(
            "--volumes-backups",
            metavar="<volumes-backups-size>",
            type=self.size_value,
            help="The new value for the volumes backups size quota limit",
        )

    def do_action(self, parsed_args):
        self.app.vinfra.compute.domain_quotas.update(
            parsed_args.domain_id,
            compute_cores=parsed_args.cores,
            compute_ram=parsed_args.ram_size,
            storage_policies=parsed_args.storage_policies,
            volumes_backups=parsed_args.volumes_backups
        )
