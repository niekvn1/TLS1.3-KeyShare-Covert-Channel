import sys
import socket
import subprocess


def createInterface(name, ip):
    subprocess.call(["ip", "link", "add", "name", name, "type", "dummy"])
    subprocess.call(["ip", "addr", "add", ip, "dev", name])
    subprocess.call(["ip", "link", "set", name, "up"])
    subprocess.call(["ethtool", "--offload", name, "tx", "off"])
    # sudo sysctl -w net.ipv4.conf.all.rp_filter=0
    # sudo sysctl -w net.ipv4.ip_forward=1


def deleteInterface(name):
    subprocess.call(["ip", "link", "del", name])


def client():
    createInterface("tlsc", "10.0.0.1/24")


def cleanClient():
    deleteInterface("tlsc")


def server():
    createInterface("tlsc", "10.0.0.2/24")


def cleanServer():
    deleteInterface("tlsc")


if __name__ == "__main__":
    l = len(sys.argv)
    if l >= 2:
        if sys.argv[1] == "client":
            if l == 3 and sys.argv[2] == "clean":
                cleanClient()
            else:
                client()
        elif sys.argv[1] == "server":
            if l == 3 and sys.argv[2] == "clean":
                cleanServer()
            else:
                server()
    else:
        print("Usage: python3 setup.py <client/server> [clean]")
