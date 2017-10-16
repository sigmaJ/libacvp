import socket
import sys
import argparse

DEFAULT_PORT = 9999

def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", dest="port", metavar="PORT", type=int, default = DEFAULT_PORT)
    return parser.parse_args()

def main():
    args = parseArgs()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", args.port))
    s.listen(1)
    
    conn, addr = s.accept()
    
    print("Connection from " + str(addr))
    s.close()
    conn.close()





if __name__ == "__main__":
    main()
