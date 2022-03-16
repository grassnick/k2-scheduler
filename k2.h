#ifndef K2_SCHEDULER_K2_H
#define K2_SCHEDULER_K2_H

/**
 * @brief simple struct to encode ioctl requests
 */
struct k2_ioctl {
    const char* dev_name;
    __u32 dev_name_len;

    union {
        char* string_in;
        __u32 u32_in;
    };

    union {
        char* string_ret;
        __u32 u32_ret;
    };
};

/*
 * I don't get how dynamic ioctl number handling is supposed to work, and at this point, I am too afraid to ask.
 * For now, this seems to work on my machine (TM).
 */
#define K2_IOCTL_MAGIC 'W'
#define K2_IOC_GET_VERSION _IOR(K2_IOCTL_MAGIC, 1, int)
#define K2_IOC_READ_TEST _IOR(K2_IOCTL_MAGIC, 6, __u32)
#define K2_IOC_WRITE_TEST _IOW(K2_IOCTL_MAGIC, 7, __u32)
#define K2_IOC_WRITE_READ_TEST _IOWR(K2_IOCTL_MAGIC, 8, __u32)

#define K2_IOC_CURRENT_INFLIGHT_LATENCY _IOWR(K2_IOCTL_MAGIC, 9, struct k2_ioctl)



#endif//K2_SCHEDULER_K2_H
