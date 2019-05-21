
from os import read
from ctypes import CDLL, \
        c_char_p, c_uint, c_int, c_void_p, \
        create_string_buffer

libec = None

def prepare():
    global libec
    libec = CDLL('liboiocore.so.0')
    libec.ecp_job_init.argtypes = (c_int, c_int, c_int)
    libec.ecp_job_init.restype = c_void_p
    libec.ecp_job_fd.argtypes = (c_void_p,)
    libec.ecp_job_fd.restype = c_int
    libec.ecp_job_status.argtypes = (c_void_p,)
    libec.ecp_job_status.restype = c_int
    libec.ecp_job_encode.argtypes = (c_void_p,)
    libec.ecp_job_decode.argtypes = (c_void_p,)
    libec.ecp_job_close.argtypes = (c_void_p,)

def compute(algo, k, m):
    if not libec:
        prepare()
    job = libec.ecp_job_init(algo, k, m)
    # TODO: feed the input
    try:
        libec.ecp_job_encode(job)

        fd = libec.ecp_job_fd(job)
        print "fd", fd
        rc = read(fd, 8)
        print "read", repr(rc)
        rc = libec.ecp_job_status(job)
        print "status", repr(rc)
    except Exception as ex:
        print ex
        libec.ecp_job_close(job)
    print "exiting"

def main():
    compute(1, 6, 3)

if __name__ == '__main__':
    main()
