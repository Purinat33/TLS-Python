from ca import *
from server import *
from client import *


def main():

    root_ca = CA()
    server = Server(
        ca=root_ca
    )
    client = Client(
        ca=root_ca
    )


if __name__ == "__main__":
    main()
