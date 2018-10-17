from metasploit.msfrpc import MsfRpcClient
# import pymsfrpc





class preModule():

    def __init__(self,msf_rpc_client):
        self.msf_client = msf_rpc_client

    def run(self,port, module, commands):
        splited_module = module.split('/',1)
        print splited_module
        self.msf_client.modules.use(splited_module[0],splited_module[1])

