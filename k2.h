#ifndef K2_SCHEDULER_K2_H
#define K2_SCHEDULER_K2_H

/**
 * @brief simple struct to encode ioctl requests
 */
#define K2_IOCTL_BLK_DEV_NAME_LENGTH 32
#define K2_IOCTL_CHAR_PARAM_LENGTH 64
struct k2_ioctl {
    const char* blk_dev;

    union {
        char* string_param;
        __u32 u32_param;
        pid_t task_pid;
    };

    union {
      __u32 interval_ns;
    };
};

/*
 * I don't get how dynamic ioctl number handling is supposed to work, and at this point, I am too afraid to ask.
 * For now, this seems to work on my machine (TM).
 */
#define K2_IOCTL_MAGIC 'W'
#define K2_IOC_GET_VERSION _IOWR(K2_IOCTL_MAGIC, 1, struct k2_ioctl)
#define K2_IOC_GET_DEVICES _IOWR(K2_IOCTL_MAGIC, 2, struct k2_ioctl)

#define K2_IOC_REGISTER_PERIODIC_TASK _IOR(K2_IOCTL_MAGIC, 7, struct k2_ioctl)
#define K2_IOC_UNREGISTER_PERIODIC_TASK _IOR(K2_IOCTL_MAGIC, 8, struct k2_ioctl)
#define K2_IOC_UNREGISTER_ALL_PERIODIC_TASKS _IOR(K2_IOCTL_MAGIC, 12, struct k2_ioctl)



#endif//K2_SCHEDULER_K2_H
