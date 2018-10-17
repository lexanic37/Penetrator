import yaml

from msfModules.pre_module import *


class Kernel():
    def __init__(self, name_workspace):
        self.config = self.get_config()
        self.msfrpc_client = self.connect_to_msfrpc()
        self.create_workspace(name_workspace)
        self.pre_module = preModule(self.msfrpc_client)
        self.data_to_modules = self.parse_config()

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
        for port, data_port in self.data_to_modules.iteritems():
            for exp_with_commands in data_port['main-modules']:
                for exploit, commands in exp_with_commands.iteritems():
                    self.pre_module.run(port, exploit, commands['commands'])

    def connect_to_msfrpc(self):
        client = MsfRpcClient(str(self.config['msfrpc']['password']))
        return client

    def create_workspace(self, name_workspace):
        db = self.msfrpc_client.db
        # db.connect('msf', database='msf', password='qkRJrU6+SAHO45NcueBhfzSc3JaPpDbiLLQgYrIOg2Y==')
        db.workspaces.add(name_workspace)
        db.workspaces.set(name_workspace)


kernel = Kernel('deployment')

kernel.run_pre_module()
# kernel.create_workspace()
