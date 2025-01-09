#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : honeypot.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Feb 2023


import argparse
import socket
import threading
import traceback
import os
import datetime
import base64
import sqlite3
import requests
import socket
import sys
import struct
from platform import uname


def get_ip_address_of_interface(ifname):
    if sys.platform == "win32":
        return None
    elif sys.platform == "linux" and "microsoft" not in uname().release.lower() and "microsoft" not in uname().version.lower():
        import fcntl
        if type(ifname) == str:
            ifname = bytes(ifname, "utf-8")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        SIOCGIFADDR = 0x8915
        try:
            ifname = struct.pack('256s', ifname[:15])
            a = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifname)[20:24]
            return socket.inet_ntoa(a)
        except OSError as e:
            return None
    else:
        return None


def get_ip_address_to_target_remote_host(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        return s.getsockname()[0]
    except Exception as e:
        return None


def can_listen_on_port(listen_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.bind((listen_ip, port))
        s.listen(5)
        s.close()
        return True
    except OSError as e:
        return False


def get_ip_addr_to_listen_on(options):
    # Getting IP address to listen on
    listening_ip = None
    if options.ip_address is not None:
        listening_ip = options.ip_address
    elif options.interface is not None:
        listening_ip = get_ip_address_of_interface(options.interface)
        if listening_ip is None:
            print("[!] Could not get IP address of interface '%s'" % options.interface)
    return listening_ip


class Reporter(object):
    """
    Reporter class is responsible for handling and reporting the data collected by the honeypot.
    
    Attributes:
        databasefile (str): Path to the SQLite database file.
        verbose (bool): Flag to enable verbose output.
        thlock (threading.Lock): Lock to ensure thread-safe operations.
    
    Methods:
        __init__(databasefile, verbose=False):
            Initializes the Reporter instance with the given database file and verbosity.
        
        tsprint(message):
            Prints a timestamped message in a thread-safe manner.
        
        report(data):
            Reports the collected data by inserting it into the SQLite database.
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
        try:
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
        except Exception as e:
            traceback.print_exc()


class MonitorServer(threading.Thread):
    """
    MonitorServer is a class that represents a server which monitors and handles incoming client connections.

    Attributes:
        ip (str): The IP address of the server.
        port (int): The port number on which the server listens for incoming connections.
        reporter: An instance used for logging and reporting events.
        hostname (str): The hostname of the server.
        running (bool): A flag indicating whether the server is running.
        clients (list): A list of active client connection handler threads.
        socket: The socket object used by the server to listen for incoming connections.
    """
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
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.hostname = socket.gethostname()

            self.socket.bind((self.ip, self.port))

            self.reporter.tsprint("[+] [%s:%s] Started listening" % (self.ip, str(self.port)))

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
        except Exception as e:
            traceback.print_exc()

    def requestStop(self):
        self.reporter.tsprint("[>] [%s:%-5s] Stopping server ..." % (self.ip, str(self.port)))
        self.running = False


class ConnectionHandlerThread(threading.Thread):
    """
    ConnectionHandlerThread is responsible for handling individual client connections to the MonitorServer.
    
    Attributes:
        server (MonitorServer): The server instance to which this thread is connected.
        reporter: The reporter instance used for logging and reporting events.
        clientsocket: The socket object for the client connection.
        infos (dict): A dictionary containing information about the server, client, connection time, and data.
    
    Methods:
        run(): Handles the client connection, receives data, and saves it.
        save_data(): Encodes the received data in base64 and checks if the data is an HTTP request.
    """
    def __init__(self, server: MonitorServer, ip, port, clientsocket, reporter):
        threading.Thread.__init__(self)
        self.server = server
        self.reporter = reporter
        self.clientsocket = clientsocket
        self.infos = {
            "server": {
                "ip": self.server.ip,
                "port": self.server.port
            },
            "client": {
                "ip": ip,
                "port": port
            },
            "connection_time": datetime.datetime.now().strftime("%A, %d. %B %Y %Hh%Mm%Ss"),
            "data": b'',
            "raw_data": b'',
            "http": {
                "is_http": False,
                "request": "",
                "verb": "",
                "path": ""
            }
        }

    def run(self):
        try:
            self.reporter.tsprint(
                "[+] [%s:%-5s] New connection from %s:%s !" % (
                    self.server.ip, str(self.server.port), 
                    self.infos["client"]["ip"], 
                    self.infos["client"]["port"],
                )
            )

            reading, self.infos["data"] = True, b''
            while reading:
                try:
                    r = self.clientsocket.recv(2048)
                    if len(r) != 0:
                        self.infos["data"] += r
                    else:
                        reading = False
                except ConnectionResetError as e:
                    reading = False

            self.reporter.tsprint(
                "[+] [%s:%-5s] Client %s:%s disconnected." % (
                    self.server.ip, str(self.server.port), 
                    self.infos["client"]["ip"], 
                    self.infos["client"]["port"],
                )
            )

            self.save_data()
        except Exception as e:
            traceback.print_exc()

    def save_data(self):
        self.infos["b64rawdata"] = base64.b64encode(self.infos["data"]).decode('ISO-8859-1')

        first_line = self.infos["data"].strip().split(b'\n')[0]

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

        self.infos["whois"] = os.popen("whois %s" % self.infos["client"]["ip"]).read().strip()

        self.reporter.report(data=self.infos)


def parseArgs():
    parser = argparse.ArgumentParser(description="A simple TCP Honeypot")

    parser.add_argument("-p", "--port", dest="ports", action="append", default=[], required=True, help="TCP port to listen on.")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    
    # Listener
    group_listener = parser.add_mutually_exclusive_group(required=False)
    group_listener.add_argument("-i", "--interface", default=None, help="Interface to listen on incoming connections.")
    group_listener.add_argument("-I", "--ip-address", default=None, help="IP address to listen on incoming connections.")

    return parser.parse_args()


if __name__ == '__main__':
    options = parseArgs()

    reporter = Reporter(databasefile="database_honeypot.db", verbose=options.verbose)

    # Remove duplicates and cast to integer
    options.ports = list(map(int, list(set(options.ports))))

    listen_on_ip = get_ip_addr_to_listen_on(options)

    if listen_on_ip is not None:
        print("[+] Listening on ports %s ..." % options.ports)
        started_servers = []
        for port in options.ports:
            if 0 < port <= 65535:
                server = MonitorServer(
                    ip=listen_on_ip,
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
    else:
        print("[!] Could not determine IP or interface to bind on. Please specify it directy with -i <interface> or -I <ip-address>.")
