from settings import *


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    s.send(b"Hello")


if __name__ == '__main__':
    main()
