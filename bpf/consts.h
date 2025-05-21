// bpf/consts.h

#ifndef __CONSTS_H
#define __CONSTS_H

#define MAX_PATH_LEN 384
#define MAX_PROCESS_NAME_LEN 32

enum {
    FILE_OP_READ = 0,
    FILE_OP_WRITE = 1,
    FILE_OP_OTHER = 2,
};

#endif /* __CONSTS_H */
