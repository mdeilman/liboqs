gcc test_lms_nist.c \
    -I/home/mad/liboqs/src/sig_stfl/lms/external \
    -I/home/mad/liboqs/build/include \
    -L/home/mad/liboqs/build/lib \
    -Wl,-rpath,/home/mad/liboqs/build/lib \
    -loqs -lssl -lcrypto -o test_lms_nist && ./test_lms_nist