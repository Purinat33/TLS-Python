from settings import *

from ca import *


def main():
    root_ca = CA()
    root_ca.save_keys("root_ca")
    root_ca.save_cerificate()


if __name__ == '__main__':
    main()
