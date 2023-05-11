from vinfra.consts import missing
from vinfraclient.cmd.base import ShowOne
from vinfraclient.utils import find_resource


class ShowParams(ShowOne):
    _description = 'Show per-node memory parameters.'

    def configure_parser(self, parser):
        parser.add_argument(
            '--node',
            metavar='<node>',
            help='Node ID or hostname',
            required=True
        )

    def do_action(self, parsed_args):
        cluster = self.app.vinfra.get_cluster()
        node = find_resource(self.app.vinfra.nodes, parsed_args.node)
        return self.app.vinfra.memory_policies.per_node(cluster, node).show_params()


class ChangeParams(ShowOne):
    _description = 'Change per-node memory parameters.'

    def configure_parser(self, parser):
        parser.add_argument(
            '--node',
            metavar='<node>',
            help='Node ID or hostname',
            required=True
        )
        parser.add_argument(
            '--guarantee',
            metavar='<guarantee>',
            help="Guarantee, in bytes",
            default=missing
        )
        parser.add_argument(
            '--swap',
            metavar='<swap>',
            help='Swap size, in bytes, or -1 if unlimited',
            default=missing
        )
        parser.add_argument(
            '--cache-ratio',
            metavar="<cache-ratio>",
            help='Cache ratio from 0 to 1 inclusive.',
            default=missing
        )
        parser.add_argument(
            '--cache-minimum',
            metavar='<cache-minimum>',
            help='Min. cache, in bytes.',
            default=missing
        )
        parser.add_argument(
            '--cache-maximum',
            metavar='<cache-maximum>',
            help='Max. cache, in bytes.',
            default=missing
        )

    def do_action(self, parsed_args):
        cluster = self.app.vinfra.get_cluster()
        node = find_resource(self.app.vinfra.nodes, parsed_args.node)
        return self.app.vinfra.memory_policies.per_node(cluster, node).change_params(
            guarantee=parsed_args.guarantee, swap=parsed_args.swap,
            cache_ratio=parsed_args.cache_ratio,
            cache_minimum=parsed_args.cache_minimum,
            cache_maximum=parsed_args.cache_maximum,
        )


class ResetParams(ShowOne):
    _description = 'Reset per-node memory parameters to defaults.'

    def configure_parser(self, parser):
        parser.add_argument(
            '--node',
            metavar='<node>',
            help='Node ID or hostname',
            required=True
        )
        parser.add_argument(
            '--guarantee',
            action='store_const',
            dest='guarantee',
            const=None,
            default=missing
        )
        parser.add_argument(
            '--swap',
            action='store_const',
            dest='swap',
            const=None,
            default=missing
        )
        parser.add_argument(
            '--cache',
            action='store_const',
            dest='cache',
            const=None,
            default=missing
        )

    def do_action(self, parsed_args):

        def has_any():
            return any(True for x in (parsed_args.guarantee,
                                      parsed_args.swap,
                                      parsed_args.cache) if x is None)

        cluster = self.app.vinfra.get_cluster()
        node = find_resource(self.app.vinfra.nodes, parsed_args.node)
        if has_any():
            return self.app.vinfra.memory_policies.per_node(cluster, node).change_params(
                guarantee=parsed_args.guarantee, swap=parsed_args.swap,
                cache_ratio=parsed_args.cache,
                cache_minimum=parsed_args.cache,
                cache_maximum=parsed_args.cache,
            )

        return self.app.vinfra.memory_policies.per_node(cluster, node).reset_params()
