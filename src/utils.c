#include "utils.h"
#include <sys/stat.h>

void create_output_dir() {
    struct stat st = {0};
    if (stat("./out", &st) == -1) {
        mkdir("./out", 0755);
    }
}
