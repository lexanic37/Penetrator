import yaml
from ipaddress import ip_address
from msfModules.pre_module import *


class Kernel():
    def __init__(self, name_workspace, scope, path_to_scan):
        self.config = self.get_config()
        self.msfrpc_client = self.connect_to_msfrpc()

        # TODO Сделать что когда имя воркспейса тоже то подтянуть старый воркспейс а не создавать новый
        self.workspace = self.get_workspace(name_workspace)

        self.pre_module = preModule(self.msfrpc_client, self.workspace)
        self.data_to_modules = self.parse_config()

        self.import_scan_result(path_to_scan)

        #for specify manually
        # self.scope = scope
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
                    self.pre_module.run( exploit, commands['commands'], port)

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


    def import_scan_result(self, path):
        self.workspace.importfile(path)

    # def generate_scope(self, scope):
    #     '''Return IPs in IPv4 range, inclusive.'''
    #     start = scope.split('-')[0]
    #     end = scope.split('-')[1]
    #     start_int = int(ip_address(start).packed.encode('hex'), 16)
    #     end_int = int(ip_address(end).packed.encode('hex'), 16)
    #     return [ip_address(ip).exploded for ip in range(start_int, end_int)]


kernel = Kernel('deployment','scan_nmap' , u'192.168.1.240-192.168.2.5')

kernel.run_pre_module()
# kernel.create_workspace()
