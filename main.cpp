#include "utils/configfs_log.h"
#include "configfs/configfs.h"

int main(int argc, char* argv[]) {
    return configfs_loop(argv);
}

