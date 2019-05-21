
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
    libec.ecp_job_set_original.argtypes = (c_void_p, c_void_p, c_int)

def compute(algo, k, m, data):
    if not libec:
        prepare()
    job = libec.ecp_job_init(algo, k, m)

    libec.ecp_job_set_original(job, data, len(data))

    try:
        libec.ecp_job_encode(job)
        fd = libec.ecp_job_fd(job)
        read(fd, 8)
        rc = libec.ecp_job_status(job)
    except Exception as ex:
        print exalgo_JERASURE_RS_VAND
    finally:
        libec.ecp_job_close(job)
    print "rc", rc

def main():
    prepare()
    for algo in (c_int.in_dll(libec, "algo_LIBERASURECODE_RS_VAND"),
                 c_int.in_dll(libec, "algo_JERASURE_RS_VAND"),
                 c_int.in_dll(libec, "algo_JERASURE_RS_CAUCHY"),
                 c_int.in_dll(libec, "algo_ISA_L_RS_VAND"),
                 c_int.in_dll(libec, "algo_ISA_L_RS_CAUCHY"),
                 c_int.in_dll(libec, "algo_SHSS"),
                 c_int.in_dll(libec, "algo_LIBPHAZR")):
        compute(algo, 6, 3, "plop")
        compute(algo, 6, 3, b"plop")

if __name__ == '__main__':
    main()
