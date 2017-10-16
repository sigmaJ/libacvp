import socket
import sys
import argparse


DEFAULT_PORT = 9999


def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", dest="port", metavar="PORT", type=int, default = DEFAULT_PORT)
    parser.add_argument("-c", dest="host", metavar="HOST", type=str, default = "localhost")
    return parser.parse_args()
    
def main():
    args = parseArgs()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    s.connect((args.host, args.port))
    print("Connected to " + args.host)
    s.close()


if __name__ == "__main__":
    main()
