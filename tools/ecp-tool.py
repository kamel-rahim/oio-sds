#!/usr/bin/env python

import eventlet
from oio import ecp

def _concurrent_test():
    for i in range(100):
        print "concurent_function"

def print_result(encode, algo, k, m, data, verbose=False):
        try:
            f = encode(algo, k, m, data, verbose=verbose)
            print "OK", repr(f)
        except Exception as ex:
            print "ERROR", repr(ex)

def main():
    algo = ecp.algo_LIBERASURECODE_RS_VAND
    pool = eventlet.GreenPool()
    pool.spawn(_concurrent_test)
    pool.spawn(print_result, ecp.concurrent_encode, algo,
               6, 4, "plop", True)
    pool.spawn(_concurrent_test)
    pool.waitall()

if __name__ == '__main__':
    main()
