from metasploit.msfrpc import MsfRpcClient


# import pymsfrpc


class preModule():
    def __init__(self, msf_rpc_client, ):
        self.msf_client = msf_rpc_client
        self.workspace = workspace

    def run(self, module_name, commands, scope, port):
        splited_module = module_name.split('/', 1)

        module = self.msf_client.modules.use(splited_module[0], splited_module[1])
        for command in commands:
            for option, value in command.iteritems():
                if value=='<RHOSTS>':
                    value = value.replace('<RHOSTS>', scope)
                elif value=='<RPORT>':
                    value = value.replace('<RPORT>', str(port))
                module[option] = value
                # print module[option]

        print module.execute()