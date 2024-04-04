import yaml

from vinfra import exceptions as vinfra_exceptions
from vinfraclient import utils
from vinfraclient.cmd import base

def node_arg(parser):
    parser.add_argument(
        "node",
        help="Node ID or hostname."
    )


def filebeat_config_mode(parser):
    config_mode = parser.add_mutually_exclusive_group()
    config_mode.add_argument(
        "--filename",
        metavar='FILENAME',
        help="Filebeat config filename (path to file) to upload."
    )
    config_mode.add_argument(
        "--elasticsearch",
        action="store_true",
        help="Set options for predefined Filebeat config (Elasticsearch template).'"
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        required=False,
        help="Restart Filebeat service for applying new config"
    )

def elasticsearch_options(parser):
    parser.add_argument(
        "--host",
        metavar='HOST',
        help="Elasticsearch hostname or ip address."
    )
    parser.add_argument(
        "--port",
        default="9200",
        metavar='PORT',
        required=False,
        help="Elasticsearch port (default is 9200)."
    )
    parser.add_argument(
        "--username",
        metavar='USERNAME',
        help="Elasticsearch username."
    )
    parser.add_argument(
        "--password",
        metavar='PASSWORD',
        help="Elasticsearch password."
    )

class ShowFilebeat(base.ShowOne):
    _description = "Show Filebeat config."
    _default_fields = ['id', 'name', 'is_active', 'is_enabled', 'state', 'config']

    def configure_parser(self, parser):
        node_arg(parser)

    def do_action(self, parsed_args):
        node = utils.find_resource(self.app.vinfra.nodes, parsed_args.node)
        return self.app.vinfra.filebeat.get(node.id)

class SetFilebeatConfig(base.TaskCommand):
    _description = 'Set Filebeat config on specified node.'

    @staticmethod
    def _get_config_from_file(filename):
        try:
            with open(filename) as stream:
                return yaml.safe_load(stream)
        except IOError as err:
            raise vinfra_exceptions.VinfraError(
                'Cannot open Filebeat configuration file {}: {}'.format(
                    filename, err
                )
            )

    def configure_parser(self, parser):
        node_arg(parser)
        filebeat_config_mode(parser)
        elasticsearch_options(parser)

    def do_action(self, parsed_args):
        node = utils.find_resource(self.app.vinfra.nodes, parsed_args.node)
        if parsed_args.filename:
            config = self._get_config_from_file(parsed_args.filename)
            return self.app.vinfra.filebeat.put_raw_config_on_node(
                node, config, parsed_args.restart
            )
        elif parsed_args.elasticsearch:
            return self.app.vinfra.filebeat.put_elasticsearch_options_on_node(
                node, parsed_args.host, parsed_args.port,
                parsed_args.username, parsed_args.password,
                parsed_args.restart
            )

class StartFilebeatService(base.TaskCommand):
    _description = "Start Filebeat service on specified node."

    def configure_parser(self, parser):
        node_arg(parser)

    def do_action(self, parsed_args):
        node = utils.find_resource(self.app.vinfra.nodes, parsed_args.node)
        rv = self.app.vinfra.filebeat.start_async(node.id)
        return rv

class StopFilebeatService(base.TaskCommand):
    _description = "Stop Filebeat service on specified node."

    def configure_parser(self, parser):
        node_arg(parser)

    def do_action(self, parsed_args):
        node = utils.find_resource(self.app.vinfra.nodes, parsed_args.node)
        return self.app.vinfra.filebeat.stop_async(node.id)

class RestartFilebeatService(base.TaskCommand):
    _description = "Restart Filebeat service on specified node."

    def configure_parser(self, parser):
        node_arg(parser)

    def do_action(self, parsed_args):
        node = utils.find_resource(self.app.vinfra.nodes, parsed_args.node)
        return self.app.vinfra.filebeat.restart_async(node.id)

class EnableFilebeatService(base.TaskCommand):
    _description = "Enable Filebeat service on specified node."

    def configure_parser(self, parser):
        node_arg(parser)

    def do_action(self, parsed_args):
        node = utils.find_resource(self.app.vinfra.nodes, parsed_args.node)
        return self.app.vinfra.filebeat.enable_async(node.id)

class DisableFilebeatService(base.TaskCommand):
    _description = "Disable Filebeat service on specified node."

    def configure_parser(self, parser):
        node_arg(parser)

    def do_action(self, parsed_args):
        node = utils.find_resource(self.app.vinfra.nodes, parsed_args.node)
        return self.app.vinfra.filebeat.disable_async(node.id)
