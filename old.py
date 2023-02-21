#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          :
# Author             :
# Date created       :
# Date last modified :
# Python Version     : 3.*

import socket
from threading import *
import os
import datetime, json, base64


class MonitorServer(Thread):
    """docstring for MonitorServer."""

    def __init__(self, port: int):
        Thread.__init__(self)
        self.port = port
        self.ip = None
        self.hostname = None
        self.running = True
        self.clients = []
        self.socket = None

    def run(self):
        self.prepare_env()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.hostname = socket.gethostname()
        try:
            self.ip = socket.getsockname()[0]
        except:
            self.ip = '127.0.0.1'
        self.socket.bind((socket.gethostname(), self.port))
        print("\x1b[1m[\x1b[93mSERVER\x1b[0m\x1b[1m]\x1b[0m Waiting for incomming connections ...")
        print("\x1b[1m[\x1b[93mSERVER\x1b[0m\x1b[1m]\x1b[0m Port : %d" % self.port)
        while self.running:
            self.socket.listen(10)
            (clientsocket, (ip, port)) = self.socket.accept()
            newthread = ConnectionHandlerThread(self, ip, port, clientsocket)
            newthread.start()
            self.clients.append(newthread)

    def prepare_env(self):
        """Documentation for prepare"""
        if not os.path.exists('../captures/%d/' % self.port):
            os.makedirs('../captures/%d/' % self.port, exist_ok=True)
        return

    def requestStop(self):
        self.running = False


class ConnectionHandlerThread(Thread):
    """docstring for ConnectionHandlerThread."""

    def __init__(self, server: MonitorServer, ip, port, clientsocket):
        Thread.__init__(self)
        self.server = server
        self.clientsocket = clientsocket
        self.infos = {
            'server': {'ip': self.server.ip, 'port': self.server.port},
            'client': {'ip': ip, 'port': port},
            'connection_time': datetime.datetime.now().strftime("%A, %d. %B %Y %Hh%Mm%Ss"),
            'data': b'',
            'raw_data': b''
        }

    def run(self):
        print("\x1b[1m[\x1b[93m+\x1b[0m\x1b[1m]\x1b[0m New connection from %s:%s !" % (self.infos['client']['ip'], self.infos['client']['port'],))
        reading, self.infos['data'] = True, b''
        while (reading == True):
            try:
                r = self.clientsocket.recv(2048)
                if len(r) != 0:
                    self.infos['data'] += r
                else:
                    reading = False
            except ConnectionResetError as e:
                reading = False
        print("\x1b[1m[\x1b[93m+\x1b[0m\x1b[1m]\x1b[0m Client %s:%s disconnected." % (self.infos['client']['ip'], self.infos['client']['port'],))
        self.save_data()

    def save_data(self):
        self.infos['raw_data'] = base64.b64encode(self.infos['data']).decode('ISO-8859-1')
        self.infos['data'] = self.infos['data'].decode('ISO-8859-1')
        whois_data = os.popen("whois %s" % self.infos['client']['ip']).read()
        self.infos['whois'] = whois_data
        if not os.path.exists('../captures/%d/%s/' % (self.server.port, self.infos['client']['ip'])):
            os.makedirs('../captures/%d/%s/' % (self.server.port, self.infos['client']['ip']), exist_ok=True)
        filename = '../captures/%d/%s/' % (self.server.port, self.infos['client']['ip'])
        filename += datetime.datetime.now().strftime("%Y_%m_%d_%Hh%Mm%Ss")
        filename += '_%s_%d' % (self.infos['client']['ip'], int(self.infos['client']['port']),)
        filename += '.json'
        f = open(filename, 'w')
        f.write(
            json.dumps(self.infos, indent=4)
        )
        f.write('\n')
        f.close()


import sys

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage : python3 " + sys.argv[0] + " port_number")
    else:
        port = int(sys.argv[1])
        if 0 < port <= 65535:
            MonitorServer(port).start()
        else:
            print("Invalid port !")
