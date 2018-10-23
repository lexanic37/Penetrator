from metasploit.msfrpc import MsfRpcClient


# import pymsfrpc


class preModule():

    def __init__(self, msf_rpc_client, workspace):
        self.msf_client = msf_rpc_client
        self.workspace = workspace
        self.result_manager = ScanResultsManager(workspace)

    def run(self, module_name, commands, port, scope):
        splited_module = module_name.split('/', 1)
        module = self.msf_client.modules.use(splited_module[0], splited_module[1])
        for command in commands:
            for option, value in command.iteritems():
                if value == '<RPORT>':
                    value = value.replace('<RPORT>', str(port))

                module[option] = value
        module["RHOSTS"] = scope
        print module['RPORT']
        print(module.execute())
        self.result_manager.get_scan_result(port)




        # TODO to manually run
        # def run_manual(self, scope, port, commands):
        #     for command in commands:
        #         for option, value in command.iteritems():
        #             if value == '<RHOSTS>':
        #                 value = value.replace('<RHOSTS>', scope)
        #             elif value == '<RPORT>':
        #                 value = value.replace('<RPORT>', str(port))





class ScanResultsManager():
    def __init__(self, workspace):
        self.workspace = workspace

    def get_scan_result(self, port):
        for result in self.workspace.vulns.list:
            if result['port'] == port:
                print result

            # scan_result = {'ip': result['host'], 'info':[{'service': port, 'status':'scanning','pre-module-result':name or creds, 'main-module-result':'', 'post-module-results':'' },
            #                                              {'service': port, 'status': 'scanning', 'pre-module-result': name or creds, 'main-module-result': '','post-module-results':''}]}





            # print self.workspace.vulns.list



