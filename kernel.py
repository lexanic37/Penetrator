import yaml
from ipaddress import ip_address
from msfModules.pre_module import *


class Kernel():
    def __init__(self, name_workspace, path_to_scan, scope):
        self.config = self.get_config()
        self.msfrpc_client = self.connect_to_msfrpc()

        # TODO make check on created workspace
        self.workspace = self.get_workspace(name_workspace)

        self.data_to_modules = self.parse_config()

        self.import_scan_result(path_to_scan)
        self.pre_module = preModule(self.msfrpc_client, self.workspace)

        # for specify manually
        self.scope = scope
        print(self.msfrpc_client.jobs)
        # self.scope_list = self.generate_scope(scope)

    def get_config(self):
        with open("config.yml", 'r') as ymlfile:
            return yaml.load(ymlfile)

    def parse_config(self):
        data_to_modules = self.config['ports'].copy()
        for port in self.config['ports']:

            port = str(port)
            if ',' in port:

                scope_ports = port.split(',')
                for i in scope_ports:
                    pass
                    data_to_modules[i] = self.config['ports'][port]
                del data_to_modules[port]

        return data_to_modules

    def run_pre_module(self):

        print self.data_to_modules
        for port, data_port in self.data_to_modules.iteritems():
            for exp_with_commands in data_port['pre-modules']:
                for exploit, commands in exp_with_commands.iteritems():
                    self.pre_module.run(exploit, commands['commands'], port,self.generate_scope_for_port(port))

    def connect_to_msfrpc(self):
        client = MsfRpcClient(str(self.config['msfrpc']['password']))
        return client

    def get_workspace(self, name_workspace):
        db = self.msfrpc_client.db
        # db.connect('msf', database='msf', password='qkRJrU6+SAHO45NcueBhfzSc3JaPpDbiLLQgYrIOg2Y==')
        db.workspaces.add(name_workspace)
        db.workspaces.set(name_workspace)
        workspace = db.workspaces.workspace(name_workspace)

        return workspace

    def generate_scope_for_port(self, port):
        ip_list = ''
        services = self.workspace.services.find(port=port)
        for service in services:
            ip_list += ' ' + service['host']

        return ip_list

    def import_scan_result(self, path):
        self.workspace.importfile(path)

        # def generate_scope_list(self, scope):
        #     '''Return IPs in IPv4 range, inclusive.'''
        #     start = scope.split('-')[0]
        #     end = scope.split('-')[1]
        #     start_int = int(ip_address(start).packed.encode('hex'), 16)
        #     end_int = int(ip_address(end).packed.encode('hex'), 16)
        #     return [ip_address(ip).exploded for ip in range(start_int, end_int)]


kernel = Kernel('deployment', 'scan_nmap', '')

kernel.run_pre_module()
# kernel.create_workspace()
