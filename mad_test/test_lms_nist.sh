for variant in \
	    LMS_SHA256_N24_H5_W1 LMS_SHA256_N24_H5_W8 \
	        LMS_SHAKE_N32_H5_W1 LMS_SHAKE_N32_H5_W8 \
		    LMS_SHAKE_N24_H5_W1 LMS_SHAKE_N24_H5_W8; do
    result=$(~/liboqs/build/tests/test_sig_stfl $variant 2>&1 | \
	                 grep -E "Passed|Failed|not enabled" | tail -1)
        echo "$variant: $result"
done
