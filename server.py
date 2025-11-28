from settings import *


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connection with {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(data)


if __name__ == '__main__':
    main()
