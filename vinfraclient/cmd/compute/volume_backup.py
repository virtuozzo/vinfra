from vinfraclient.cmd.base import Lister, ShowOne, TaskCommand
from vinfraclient import utils


def _volume_backup_arg(parser):
    parser.add_argument(
        "volume_backup",
        metavar="<volume-backup>",
        help="Volume backup ID or name"
    )


class ListVolumeBackups(Lister):
    _description = "List compute volume backups."
    _default_fields = ['id', 'name', 'status', 'volume_id']

    def configure_parser(self, parser):
        parser.add_argument(
            '--id',
            metavar='<id>',
            action='filter',
            operators=('in', 'contains'),
            help='Show a backup with the specified ID or list backups using '
                 'a filter.'
        )
        parser.add_argument(
            '--name',
            metavar='<name>',
            action='filter',
            operators='contains',
            help='List backups with the specified name or use a filter.'
        )
        parser.add_argument(
            "--volume",
            metavar="<volume>",
            help="List backups with the specified volume ID or name."
        )
        parser.add_argument(
            "--backup-plan",
            metavar="<backup-plan>",
            help="List backups with the specified backup plan ID or name."
        )
        parser.add_argument(
            "--status",
            metavar="<status>",
            help="List backups with the specified status."
        )
        parser.add_argument(
            '--project',
            metavar='<project>',
            action='filter',
            operators='in',
            help='List backups that belong to projects with the specified names or IDs. '
                 'Can only be performed by system administrators.'
        )
        parser.add_argument(
            "--domain",
            metavar="<domain>",
            help='List backups that belong to a domain with the specified name or ID. '
                 'Can only be performed by system administrators.'
        )

    def do_action(self, parsed_args):
        filters = {}
        if parsed_args.id:
            filters['id'] = parsed_args.id
        if parsed_args.name:
            filters['name'] = parsed_args.name
        if parsed_args.volume:
            volume = utils.find_resource(self.app.vinfra.compute.volumes,
                                         parsed_args.volume)
            filters['volume_id'] = volume.id
        if parsed_args.backup_plan:
            backup_plan = utils.find_resource(self.app.vinfra.compute.backup_plans,
                                              parsed_args.backup_plan)
            filters['backup_plan_id'] = backup_plan.id
        if parsed_args.status:
            filters['status'] = parsed_args.status
        if parsed_args.project:
            manager = self.app.vinfra.compute.projects
            filters['project_id'] = utils.validate_resources_from_operator(
                manager, parsed_args.project)
        if parsed_args.domain:
            domain = utils.find_resource(self.app.vinfra.domains, parsed_args.domain)
            filters['domain_id'] = domain.id
        return self.app.vinfra.compute.volume_backups.list(filters=filters)


class ShowVolumeBackup(ShowOne):
    _description = "Show details of a compute volume backup."

    def configure_parser(self, parser):
        _volume_backup_arg(parser)

    def do_action(self, parsed_args):
        backup = utils.find_resource(
            self.app.vinfra.compute.volume_backups,
            parsed_args.volume_backup
        )
        return backup


class CreateVolumeBackup(TaskCommand):
    _description = "Create a new compute volume backup."

    def configure_parser(self, parser):
        parser.add_argument(
            "volume",
            metavar="<volume>",
            help="Volume ID or name"
        )
        parser.add_argument(
            "--name",
            metavar="<name>",
            help="Volume backup name"
        )
        parser.add_argument(
            "--description",
            metavar="<description>",
            help="Volume backup description"
        )

    def do_action(self, parsed_args):
        manager = self.app.vinfra.compute.volume_backups
        volume = utils.find_resource(
            self.app.vinfra.compute.volumes, parsed_args.volume
        )
        backup = manager.create_async(
            volume.id,
            name=parsed_args.name,
            description=parsed_args.description
        )
        return backup


class DeleteVolumeBackup(TaskCommand):
    _description = "Delete a compute volume backup."

    def configure_parser(self, parser):
        _volume_backup_arg(parser)

    def do_action(self, parsed_args):
        backup = utils.find_resource(
            self.app.vinfra.compute.volume_backups,
            parsed_args.volume_backup
        )
        return backup.delete_async()


class RestoreVolumeBackup(TaskCommand):
    _description = "Restore a compute volume from a backup."

    def configure_parser(self, parser):
        _volume_backup_arg(parser)
        parser.add_argument(
            "--name",
            metavar="<name>",
            required=False,
            help="Name of a new volume"
        )
        parser.add_argument(
            "--storage-policy",
            metavar="<storage-policy>",
            required=False,
            help="The name or ID of storage policy for a new volume"
        )

    def do_action(self, parsed_args):
        backup = utils.find_resource(
            self.app.vinfra.compute.volume_backups,
            parsed_args.volume_backup
        )
        return backup.restore_async(name=parsed_args.name,
                                    storage_policy=parsed_args.storage_policy)
