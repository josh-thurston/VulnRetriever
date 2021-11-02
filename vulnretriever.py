import jmespath
import nmap3
import uuid
import pandas as pd
from datetime import datetime, date
from mitrecve import crawler


class VulnRetriever(object):

    @classmethod
    def scan(cls, address):
        """
        :param address: Target IP Address to scan
        :return:
        """
        reportlist = []
        status_result = VulnRetriever.ping(address)
        if status_result == 'up':
            Logger.log("Ping Success")
            VulnRetriever.up(address)
        else:
            Logger.log("Ping Failed")
            scanid = uuid.uuid4().hex
            scan_results = [scanid, datetime.now(), address, "Down", "", "", "", "", "", "", "", ""]
            reportlist.append(scan_results)
            Reporter.record(reportlist)

    @classmethod
    def up(cls, address):
        """
        :param address:
        :return:
        """

        reportlist = []
        Logger.log("Start Nmap Scan")
        nmap = nmap3.NmapScanTechniques()
        results = nmap.nmap_tcp_scan(address, args="-sV --script vulners --script-args mincvss+5.0")
        base = jmespath.search(f'"{address}"', results)
        Logger.log("Scanning TCP Ports")
        tcp_ports = jmespath.search('ports[*].portid', base)
        portcount = len(tcp_ports) - 1
        x = -1
        while x < portcount:
            x = x + 1
            scan_results = []
            scanid = uuid.uuid4().hex
            scan_results.append(scanid)
            Logger.log(f"Create Scan ID")
            scan_results.append(datetime.now())
            scan_results.append(address)
            scan_results.append("Up")
            protocol = VulnRetriever.get_protocols(x, base)
            scan_results.append(protocol)
            portid = VulnRetriever.get_port_ids(x, base)
            scan_results.append(portid)
            state = VulnRetriever.get_port_state(x, base)
            scan_results.append(state)
            service = VulnRetriever.get_services(x, base)
            scan_results.append(service)
            cpe = VulnRetriever.get_cpe(x, base)
            scan_results.append(cpe)
            product = VulnRetriever.get_products(x, base)
            scan_results.append(product)

            if not product:
                if not cpe:
                    pass
                else:
                    cve = VulnRetriever.get_cve(cpe)
                    if not cve:
                        scan_results.append("")
                        scan_results.append("")
                    else:
                        scan_results.append(cve)

            else:
                cve = VulnRetriever.get_cve(product)
                if not cve:
                    scan_results.append("")
                    scan_results.append("")
                else:
                    scan_results.append(cve)

            Logger.log("Updating Scan Report")
            reportlist.append(scan_results)
            Reporter.record(reportlist)

    @staticmethod
    def get_cve(arg1):
        """

        :param arg1: Accept Product, Product + Version, or CPE
        :return:
        """
        Logger.log("Get CVE")
        cves = crawler.get_main_page(arg1)
        if not cves:
            cve = ""
            Logger.log("No CVE")
        else:
            newest = cves[0]
            cve = str(newest[0])
            Logger.log("Found CVE")
        Logger.log(cve)
        return cve

    @staticmethod
    def get_cpe(x, base):
        Logger.log("Get CPE")
        cpe_results = jmespath.search(f'ports[{x}].cpe[*].cpe', base)
        if not cpe_results:
            cpe = ""
            Logger.log("No CPE")
            Logger.log(cpe)
            return cpe
        else:
            for c in cpe_results:
                cpe = str(c)
                Logger.log("Found CPE")
                Logger.log(cpe)
                return cpe

    @staticmethod
    def get_protocols(x, base):
        Logger.log("Get Protocols")
        protocol_results = jmespath.search(f'ports[{x}].protocol', base)
        if not protocol_results:
            protocol = ""
            Logger.log("No Protocol")
        else:
            protocol = protocol_results
            Logger.log("Found Protocol")
        Logger.log(protocol)
        return protocol

    @staticmethod
    def get_port_ids(x, base):
        Logger.log("Get Port ID")
        port_id_results = jmespath.search(f'ports[{x}].portid', base)
        if not port_id_results:
            port = ""
            Logger.log("No Port")
        else:
            port = str(port_id_results)
            Logger.log("Found Port")
        Logger.log(port)
        return port

    @staticmethod
    def get_port_state(x, base):
        Logger.log("Get Port State")
        port_state_results = jmespath.search(f'ports[{x}].state', base)
        if not port_state_results:
            state = ""
            Logger.log("No Port State")
        else:
            state = port_state_results
            Logger.log("Found Port State")
        Logger.log(state)
        return state

    @staticmethod
    def get_services(x, base):
        Logger.log("Get Services")
        service_results = jmespath.search(f'ports[{x}].service.name', base)
        if not service_results:
            service = ""
            Logger.log("No Service")
        else:
            service = service_results
            Logger.log("Found Service")
        Logger.log(service)
        return service

    @staticmethod
    def ping(address):
        Logger.log("Start Ping")
        nmap = nmap3.NmapScanTechniques()
        result = nmap.nmap_ping_scan(address)
        status_result = jmespath.search(f'"{address}".state.state', result)
        return status_result

    @staticmethod
    def get_products(x, base):
        Logger.log("Get Products")
        product_results = jmespath.search(f'ports[{x}].service.product', base)
        if not product_results:
            product = ""
            Logger.log("No Product")
        else:
            Logger.log("Get Product Version")
            version_results = jmespath.search(f'ports[{x}].service.version', base)
            if not version_results:
                product = product_results
                Logger.log("Found Product")
                Logger.log("No Version")
            else:
                product = f"{product_results} {version_results}"
                Logger.log("Found Product")
                Logger.log("Found Version")
        Logger.log(product)
        return product


class Reporter(object):
    report = f"reports/VulnRetriever_{date.today()}.csv"

    @classmethod
    def record(cls, reportlist):
        df = pd.DataFrame(reportlist)
        df.to_csv(cls.report, index=False, header=False, mode='a')


class Logger(object):
    logfile = f"logs/VulnRetriever.log"

    @classmethod
    def log(cls, line):
        with open(cls.logfile, 'a') as fout:
            fout.write(f"Date: {datetime.now()}, Message: {line} \n")
