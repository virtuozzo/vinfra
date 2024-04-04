from vinfraclient.cmd.base import Command, Lister, ShowOne
from vinfraclient.utils import find_resource, IntervalValue


def _backup_plan_arg(parser):
    parser.add_argument(
        "backup_plan",
        metavar="<backup-plan>",
        help="Backup plan ID or name"
    )


def _backup_plan_properties(parser):
    parser.add_argument(
        "--description",
        metavar="<description>",
        help="Backup plan description"
    )
    parser.add_argument(
        "--schedule-minute",
        metavar="<minutes>",
        help="Comma-separated list of minutes. "
             "Specify '*' to schedule backup every minute."
    )
    parser.add_argument(
        "--schedule-hour",
        metavar="<hours>",
        help="Comma-separated list of hours. "
             "Specify '*' to schedule backup every hour."
    )
    parser.add_argument(
        "--schedule-day",
        metavar="<days>",
        help="Comma-separated list of days of the month. "
             "Specify '*' to schedule backup every day."
    )
    parser.add_argument(
        "--schedule-day-of-week",
        metavar="<days-of-week>",
        help="Comma-separated list of days of the week. "
             "Specify '*' to schedule backup every week day."
    )
    parser.add_argument(
        "--schedule-week",
        metavar="<weeks>",
        help="Comma-separated list of weeks. "
             "Specify '*' to schedule backup every week."
    )
    parser.add_argument(
        "--schedule-month",
        metavar="<months>",
        help="Comma-separated list of months. "
             "Specify '*' to schedule backup every mouth."
    )
    parser.add_argument(
        "--schedule-interval",
        metavar="<interval>",
        help="Interval between backups, in hours. You can also specify the following units: "
             "'h' for hours, 'd' for days, and 'w' for weeks. "
             "Only one unit can be used at a time."
    )
    parser.add_argument(
        "--schedule-disable",
        action="store_true",
        help="Erase backup schedule."
    )
    parser.add_argument(
        "--recovery-points-rotation",
        metavar="<amount>",
        type=int,
        help="Amount of full recovery points to preserve."
    )
    parser.add_argument(
        "--disabled",
        action="store_true",
        default=None,
        help="Disable backup plan."
    )
    parser.add_argument(
        "--enabled",
        action="store_false",
        dest="disabled",
        default=None,
        help="Enable backup plan."
    )


def _arguments_to_payload(parsed_args):
    rv = {'schedule': {}, 'properties': {}}
    kwargs = vars(parsed_args)
    schedule_interval = IntervalValue(
        kwargs.pop('schedule_interval', None)).value
    if schedule_interval:
        rv['schedule']['interval'] = schedule_interval
    rv['name'] = kwargs.pop('name', None)
    rv['description'] = kwargs.pop('description', None)
    disabled = kwargs.pop('disabled', None)
    if disabled is not None:
        rv['disabled'] = disabled
    rv['properties']['recovery_points_rotation'] = kwargs.pop(
        'recovery_points_rotation', None)
    disable_schedule = kwargs.pop('schedule_disable', None)
    for k, v in kwargs.items():
        if k.startswith('schedule_'):
            rv['schedule'][k[9:]] = v
    if all(v is None for v in rv['schedule'].values()):
        rv['schedule'] = None
    if disable_schedule:
        rv['schedule'] = {}
    if all(v is None for v in rv['properties'].values()):
        rv['properties'] = None
    return rv


class ListBackupPlans(Lister):
    _description = "List compute backup plans."
    _default_fields = ['id', 'project_id', 'name', 'description',
                       'schedule', 'properties', 'status', 'disabled']
    _sort_keys = ['id', 'name', 'status']

    def configure_parser(self, parser):
        parser.add_argument(
            '--limit',
            metavar='<num>',
            type=int,
            help='The maximum number of backup plans to list.'
        )
        parser.add_argument(
            '--marker',
            metavar='<volume>',
            help='List backup plans after the marker.'
        )
        parser.add_argument(
            "--domain",
            metavar="<domain>",
            help='List backup plans that belong to a domain with the specified name or ID. '
                 'Can only be performed by system administrators.'
        )
        parser.add_argument(
            '--project',
            metavar='<project>',
            help='List backup plans that belong to projects with the specified names or IDs. '
                 'Can only be performed by system administrators.'
        )
        parser.add_argument(
            '--status',
            metavar='<status>',
            help='List backup plans with the specified status.'
        )
        parser.add_argument(
            '--name',
            metavar='<name>',
            action='filter',
            operators='contains',
            help='List backup plans with the specified name or use a filter.'
        )
        parser.add_argument(
            '--sort',
            metavar='<sort>',
            help="List backup plans sorted by key.\n"
                 "The sorting format is <sort-key>:<order>. The order is 'asc' or 'desc'.\n"
                 "Supported sort keys: {}".format(', '.join(self._sort_keys))
        )

    def do_action(self, parsed_args):
        filters = {}
        if parsed_args.domain:
            domain = find_resource(self.app.vinfra.domains, parsed_args.domain)
            filters['domain_id'] = domain.id
        if parsed_args.project:
            project = find_resource(self.app.vinfra.compute.projects, parsed_args.project)
            filters['project_id'] = project.id
        if parsed_args.status:
            filters['status'] = parsed_args.status
        if parsed_args.name:
            filters['name'] = parsed_args.name
        if parsed_args.sort:
            filters['sort'] = parsed_args.sort
        return self.app.vinfra.compute.backup_plans.list(
            limit=parsed_args.limit, marker=parsed_args.marker, filters=filters,
            sort=parsed_args.sort,
        )


class ShowBackupPlan(ShowOne):
    _description = "Show details of a compute backup plan."

    def configure_parser(self, parser):
        _backup_plan_arg(parser)

    def do_action(self, parsed_args):
        return find_resource(
            self.app.vinfra.compute.backup_plans,
            parsed_args.backup_plan
        )


class SetBackupPlan(ShowOne):
    _description = "Modify an existing compute backup plan."

    def configure_parser(self, parser):
        _backup_plan_arg(parser)
        parser.add_argument(
            "--name",
            metavar="<name>",
            help="A new name for the backup plan"
        )
        _backup_plan_properties(parser)

    def do_action(self, parsed_args):
        backup_plan = find_resource(
            self.app.vinfra.compute.backup_plans,
            parsed_args.backup_plan
        )
        payload = _arguments_to_payload(parsed_args)
        return backup_plan.update(**payload)


class CreateBackupPlan(ShowOne):
    _description = "Create a new compute backup plan."

    def configure_parser(self, parser):
        parser.add_argument(
            "name",
            metavar="<backup-plan-name>",
            help="Backup plan name"
        )
        _backup_plan_properties(parser)

    def do_action(self, parsed_args):
        manager = self.app.vinfra.compute.backup_plans
        payload = _arguments_to_payload(parsed_args)
        return manager.create(**payload)


class DeleteBackupPlan(Command):
    _description = "Delete a compute backup."

    def configure_parser(self, parser):
        _backup_plan_arg(parser)

    def do_action(self, parsed_args):
        backup_plan = find_resource(
            self.app.vinfra.compute.backup_plans,
            parsed_args.backup_plan
        )
        return backup_plan.delete()


class ListBackupPlanVolumes(Lister):
    _description = "List compute backup plan volumes."
    _default_fields = ['id', 'name', 'size', 'status', 'project_id', 'storage_policy_name']
    _sort_keys = ['id', 'name', 'size', 'status', 'created_at']

    def configure_parser(self, parser):
        parser.add_argument(
            '--limit',
            metavar='<num>',
            type=int,
            help='The maximum number of volumes to list. To list all volumes, '
                 'set the option to -1.'
        )
        parser.add_argument(
            '--marker',
            metavar='<volume>',
            help='List volumes after the marker.'
        )
        parser.add_argument(
            '--sort',
            metavar='<sort>',
            help="List volumes sorted by key.\n"
                 "The sorting format is <sort-key>:<order>. The order is 'asc' or 'desc'.\n"
                 "Supported sort keys: {}".format(', '.join(self._sort_keys))
        )
        _backup_plan_arg(parser)

    def do_action(self, parsed_args):
        backup_plan = find_resource(
            self.app.vinfra.compute.backup_plans,
            parsed_args.backup_plan
        )
        filters = {}
        if parsed_args.sort:
            filters['sort'] = parsed_args.sort
        return backup_plan.volumes.list(
            limit=parsed_args.limit,
            marker=parsed_args.marker,
            filters=filters,
        )


class AddBackupPlanVolumes(Command):
    _description = "Add volumes to a compute backup plan."

    def configure_parser(self, parser):
        _backup_plan_arg(parser)
        parser.add_argument(
            "backup_plan_volume_ids",
            metavar="<backup-plan-volume>",
            nargs='*',
            help="Volume ID"
        )

    def do_action(self, parsed_args):
        backup_plan = find_resource(
            self.app.vinfra.compute.backup_plans,
            parsed_args.backup_plan
        )
        return backup_plan.volumes.add(
            ids=parsed_args.backup_plan_volume_ids
        )


class RemoveBackupPlanVolumes(Command):
    _description = "Remove volumes from a compute backup plan."

    def configure_parser(self, parser):
        _backup_plan_arg(parser)
        parser.add_argument(
            "backup_plan_volume_ids",
            metavar="<backup-plan-volume-id>",
            nargs='*',
            help="Volume ID"
        )

    def do_action(self, parsed_args):
        backup_plan = find_resource(
            self.app.vinfra.compute.backup_plans,
            parsed_args.backup_plan
        )
        return backup_plan.volumes.remove(
            ids=parsed_args.backup_plan_volume_ids
        )
