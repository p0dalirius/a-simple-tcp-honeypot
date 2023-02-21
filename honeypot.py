#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : honeypot.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Feb 2023

import argparse
import socket
import threading
import os
import datetime
import base64
import sqlite3
import requests


VERSION = "1.0"


class Reporter(object):
    """
    Documentation for class Reporter
    """

    def __init__(self, databasefile, verbose=False):
        super(Reporter, self).__init__()
        self.databasefile = databasefile
        self.verbose = verbose
        self.thlock = threading.Lock()

    def tsprint(self, message):
        self.thlock.acquire()
        print(message)
        self.thlock.release()

    def report(self, data):
        self.thlock.acquire()
        conn = sqlite3.connect(database=self.databasefile)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results(
                source_ip VARCHAR,
                source_port INTEGER,
                client_ip VARCHAR,
                client_port INTEGER,
                connection_time VARCHAR,
                b64rawdata VARCHAR,
                whois VARCHAR,
                is_http BOOLEAN,
                http_request VARCHAR,
                http_verb VARCHAR,
                http_path VARCHAR
            );
        """)

        cursor.execute(
            "INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                data["server"]["ip"],
                data["server"]["port"],
                data["client"]["ip"],
                data["client"]["port"],
                data["connection_time"],
                data["b64rawdata"],
                data["whois"],
                data["http"]["is_http"],
                data["http"]["request"],
                data["http"]["verb"],
                data["http"]["path"]
            )
        )
        conn.commit()
        conn.close()
        self.thlock.release()


class MonitorServer(threading.Thread):
    """docstring for MonitorServer."""

    def __init__(self, ip, port: int, reporter):
        threading.Thread.__init__(self)
        self.port = port
        self.ip = ip

        self.reporter = reporter

        self.hostname = None
        self.running = True
        self.clients = []
        self.socket = None

    def run(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.hostname = socket.gethostname()

        self.socket.bind((socket.gethostname(), self.port))

        self.reporter.tsprint("[+] [%s:%-5s] Started listening " % (self.ip, str(self.port)))

        while self.running:
            self.socket.listen(10)
            (clientsocket, (ip, port)) = self.socket.accept()
            newthread = ConnectionHandlerThread(
                server=self,
                ip=ip,
                port=port,
                clientsocket=clientsocket,
                reporter=self.reporter
            )
            newthread.start()
            self.clients.append(newthread)

    def requestStop(self):
        self.reporter.tsprint("[>] [%s:%-5s] Stopping server ..." % (self.ip, str(self.port)))
        self.running = False


class ConnectionHandlerThread(threading.Thread):
    """docstring for ConnectionHandlerThread."""

    def __init__(self, server: MonitorServer, ip, port, clientsocket, reporter):
        threading.Thread.__init__(self)
        self.server = server
        self.reporter = reporter
        self.clientsocket = clientsocket
        self.infos = {
            'server': {
                'ip': self.server.ip,
                'port': self.server.port
            },
            'client': {
                'ip': ip,
                'port': port
            },
            'connection_time': datetime.datetime.now().strftime("%A, %d. %B %Y %Hh%Mm%Ss"),
            'data': b'',
            'raw_data': b'',
            'http': {
                "is_http": False,
                "request": "",
                "verb": "",
                "path": ""
            }
        }

    def run(self):
        self.reporter.tsprint("[+] [%s:%-5s] New connection from %s:%s !" % (self.server.ip, str(self.server.port), self.infos['client']['ip'], self.infos['client']['port'],))

        reading, self.infos['data'] = True, b''
        while reading:
            try:
                r = self.clientsocket.recv(2048)
                if len(r) != 0:
                    self.infos['data'] += r
                else:
                    reading = False
            except ConnectionResetError as e:
                reading = False

        self.reporter.tsprint("[+] [%s:%-5s] Client %s:%s disconnected." % (self.server.ip, str(self.server.port), self.infos['client']['ip'], self.infos['client']['port'],))

        self.save_data()

    def save_data(self):
        self.infos['b64rawdata'] = base64.b64encode(self.infos['data']).decode('ISO-8859-1')

        first_line = self.infos['data'].strip().split(b'\n')[0]

        if any([http in first_line for http in [b"HTTP/0.9", b"HTTP/1.0", b"HTTP/1.1", b"HTTP/2"]]):
            self.infos["http"]["is_http"] = True
            self.infos["http"]["request"] = first_line.decode('ISO-8859-1').strip()

            remainder = None
            if " " in self.infos["http"]["request"]:
                verb, remainder = self.infos["http"]["request"].split(' ', 1)
                self.infos["http"]["verb"] = verb

            if remainder is not None:
                if " " in remainder:
                    path, remainder = remainder.split(' ', 1)
                    self.infos["http"]["path"] = path

        self.infos['whois'] = os.popen("whois %s" % self.infos['client']['ip']).read().strip()

        self.reporter.report(data=self.infos)


def parseArgs():
    print("honeypot.py v%s - by @podalirius_\n" % VERSION)

    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-i", "--ip", dest="ip", default=None, required=False, help='IP address port to listen on.')
    parser.add_argument("-p", "--port", dest="ports", action="append", default=[], required=True, help='TCP port to listen on.')
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    return parser.parse_args()


if __name__ == '__main__':
    options = parseArgs()

    reporter = Reporter(databasefile="database_honeypot.db", verbose=options.verbose)

    # Remove duplicates and cast to integer
    options.ports = list(map(int, list(set(options.ports))))

    if options.ip is None:
        try:
            options.ip = requests.get("http://ifconfig.me/").content.decode('utf-8').strip()
        except Exception as e:
            options.ip = '0.0.0.0'

    print("[+] Listening on ports %s ..." % options.ports)
    started_servers = []
    for port in options.ports:
        if 0 < port <= 65535:
            server = MonitorServer(
                ip=options.ip,
                port=port,
                reporter=reporter
            )
            server.start()
            started_servers.append(server)
        else:
            print("[!] Skipping port %d as it is not in the TCP range." % port)

    while input("").strip() != "stop":
        pass

    for server in started_servers:
        server.requestStop()

    for server in started_servers:
        server.join()

    print("[!] Quiting.")
