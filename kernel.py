import yaml
from ipaddress import ip_address
from queue import Queue
import time

from msfModules.pre_module import *
import threading


class Kernel():
    def __init__(self, name_workspace, path_to_scan, scope):
        self.config = self.get_config()
        self.msfrpc_client = self.connect_to_msfrpc()

        # TODO make check on created workspace
        self.workspace = self.get_workspace(name_workspace)

        self.data_to_modules = self.parse_config()

        self.import_scan_result(path_to_scan)

        # for specify manually
        self.scope = scope

        self.scope_list = self.get_scope_list()
        self.job_manger = JobsManager(self.msfrpc_client)

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

    def run(self):
        # print self.data_to_modules

        workers = []
        work = {'main-module-data': []}
        for port, data_port in self.data_to_modules.iteritems():
            for exp_with_commands in data_port['pre-modules']:
                for module, commands in exp_with_commands.iteritems():
                    # self.pre_module.run(exploit, commands['commands'], port, self.generate_scope_for_port(port))
                    work['pre-module-data'] = {'module': module, 'commands': commands['commands'], 'port': port,
                                               'scope_for_port': self.generate_scope_for_port(port)}

            for exp_with_commands in data_port['main-modules']:
                for module, commands in exp_with_commands.iteritems():
                    work['main-module-data'] = work['main-module-data'].append(
                        {'module': module, 'commands': commands['commands'], 'port': port,
                         'scope_for_port': self.generate_scope_for_port(port)})

            self.job_manger.put(work)

            # work.append({'module':module, 'commands': commands['commands'], 'port': port, 'scope': self.generate_scope_for_port(port)})

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

    def get_scope_list(self):
        result = []
        for host in self.workspace.services.list:
            result.append(host['host'])
        return result

    # for scan
    def generate_scope_for_port(self, port):
        ip_list = ''
        services = self.workspace.services.find(port=port)
        for service in services:
            ip_list += ' ' + service['host']

        return ip_list

    def import_scan_result(self, path):
        self.workspace.importfile(path)


        # for manual
        # def generate_scope_list(self, scope):
        #     '''Return IPs in IPv4 range, inclusive.'''
        #
        #     start = scope.split(' ')[0]
        #     end = scope.split(' ')[1]
        #     start_int = int(ip_address(start).packed.encode('hex'), 16)
        #     end_int = int(ip_address(end).packed.encode('hex'), 16)
        #     return [ip_address(ip).exploded for ip in range(start_int, end_int)]


class JobsManager():
    def __init__(self, msfrpc_client):
        self.msfrpc_client = msfrpc_client
        self.workspace = msfrpc_client.workspace

        self.queue = []

        self.running_scans = []
        self.finished_scans = []

        self.running_explotation = []
        self.finished_explotation = []

        self.running_post_explotation = []
        self.finished_post_explotation = []

        self.last_jobs = None
        self.scan_queue = Queue()
        self.update_thread = threading.Thread(target=self.jobs_update)
        self.scan_thread = threading.Thread(target=self.worker_scans, args=(self.scan_queue,))
        self.jobs_msf_manager = msfrpc_client.jobs

        self.jobs_update()

        self.explotation_queue = []
        self.post_explotation_queue = []
        self.max_run_scans = 4

        self.pre_module = preModule(self.msfrpc_client, self.workspace)

    @property
    def jobs(self):
        return {'pre-modules': [{'exploit': 17 - 010, 'machine': [{'ip': '1.1.1.1', 'job': '1'}]}]}

    def put(self, work):
        self.queue.append(work)

    def jobs_update(self):
        # while True:

        msf_jobs = self.jobs_msf_manager.list
        print(msf_jobs)
        if msf_jobs != self.last_jobs:
            finished = {k: self.last_jobs[k] for k in set(self.last_jobs) - set(msf_jobs)}
            for id in finished:

                for scan_id in self.running_scans:
                    if scan_id == id:
                        self.finished_scans.append({ id : self.running_scans[id]})
                        self.running_scans.remove(self.running_scans[scan_id])

                for explotation_id in self.running_explotation:
                    if explotation_id == id:
                        self.finished_explotation.append({ id: self.running_explotation[id]})
                        self.running_explotation.remove(self.running_explotation[explotation_id])

                for post_explotation_id in self.running_post_explotation:
                    if post_explotation_id == id:
                        self.finished_post_explotation.append({id : self.running_post_explotation[id]})
                        self.running_post_explotation.remove(self.running_post_explotation[post_explotation_id])

        self.last_jobs = self.jobs_msf_manager.list
        time.sleep(1)

    def worker_scans(self, scan_queue):
        count_scans = 0
        while True:
            if count_scans <= self.max_run_scans:
                scan_data = scan_queue.get()
                job_id = self.pre_module.run(scan_data['module'], scan_data['commands'], scan_data['port'] , scan_data['scope_for_port'])
                self.running_scans.append({ job_id, scan_data['port']})
                scan_queue.task_done()
            else:
                time.sleep(1)

    def run(self):
        self.update_thread.start()


kernel = Kernel('deployment', 'scan_nmap', '')






# kernel.run()
# # kernel.create_workspace()

# module = self.msfrpc_client.modules.use('auxiliary', 'scanner/smb/smb_ms17_010')
#         module['RHOSTS'] = '1.1.1.1-255.1.1.1'
#         module.execute()
