
#include "configfs/configfs.h"
#include "utils/configfs_log.h"
#include <alloca.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <linux/sched.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <linux/limits.h>
#include <set>
#include <map>
#include <mutex>

class ConfigManager {
public:
    static ConfigManager& GetInstance() {
        if (instance == nullptr) {
            std::lock_guard<std::mutex> lock(servicelock);
            if (instance == nullptr) {
                instance = new ConfigManager();
            }
        }
        return *instance;
    }

    int Open(const char *path, uint64_t lockOwner) {
        std::string p(path);
        if (lockOwner != 0) {
            if (lockset.find(p) == lockset.end()) {
                lockset[p] = lockOwner;
                return 0;
            } else {
                errno = EACCES;
                return -1;
            }
        }
        return 0;
    }

    int Close(const char *path, uint64_t lockOwner) {
        std::string p(path);
        lockset.erase(p);
        return 0;
    }

    std::string Read(const char *path, uint64_t lockOwner) {
        LogW("Read file: %s", path);
        std::string p(path);
        if (!checkPermissions(path, lockOwner)) {
            errno = EPERM;
            return "No Permission!!\n";
        }
        return helpStrings[p];
    }

    int Write(const char *path, uint64_t lockOwner, const char* buf, size_t size, off_t offset) {
        std::string p(path);
        if (!checkPermissions(path, lockOwner)) {
            errno = EPERM;
            return -1;
        }
        // *******************************************
        // *** TODO: parse buf and control other process config
        // *** TIPS: use looper handler request (reduce the filesystem time use)
        // *******************************************
        LogI("Recv data: %s\n", buf);
        return size;
    }

    int ReadDir(const char *path, uint64_t lockOwner, std::set<std::string>& list) {
        LogW("[ReadDir]Read dir: %s", path);
        std::string p(path);
        if (!checkPermissions(path, lockOwner)) {
            errno = EPERM;
            return -1;
        }
        for (auto s : dirset) {
            if (s == p) {
                continue;
            }
            if (s.find(p) == 0) {
                s = s.substr(p.length());
                if (s.find("/") == 0) {
                    s = s.substr(1);
                }
                if (s.find("/") != std::string::npos) {
                    continue;
                }
                LogW("[ReadDir]list dir: %s", s.c_str());
                list.insert(s);
            }
        }
        for (auto s : fileset) {
            if (s == p) {
                continue;
            }
            if (s.find(p) == 0) {
                s = s.substr(p.length());
                if (s.find("/") == 0) {
                    s = s.substr(1);
                }
                if (s.find("/") != std::string::npos) {
                    continue;
                }
                LogW("[ReadDir]list file: %s", s.c_str());
                list.insert(s);
            }
        }
        return 0;
    }

    int GetFileType(const char *path) {
        std::string p(path);
        if (dirset.count(p) != 0) {
            return S_IFDIR;
        } else if (fileset.count(p) != 0) {
            return S_IFREG;
        } else {
            return 0;
        }
    }

    // ### Deleted Function
    // Delete copy constructor
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager & operator = (const ConfigManager&) = delete;

private:
    ConfigManager() {}
    ~ConfigManager() {
        if (instance != nullptr) {
            delete instance;
        }
        instance = nullptr;
    }

    bool checkPermissions(const char *path, uint64_t lockOwner) {
        std::string p(path);
        if (lockset.find(p) == lockset.end()) {
            return true;
        }
        if (lockset[p] != lockOwner) {
            return false;
        }
        return true;
    }

    inline static std::mutex servicelock;
    inline static ConfigManager* instance = nullptr;

    inline static std::set<std::string> dirset = {
        "/",
        "/Libary",
        "/Internal",
        "/SystemCall",
        "/BinderIPC",
        "/Signal",
    };

    inline static std::set<std::string> fileset = {
        "/readme",
        "/Libary/art_config",
        "/Libary/libc_config",
        "/SystemCall/open_config",
        "/SystemCall/write_config",
    };

    // Only file can read or write normal
    inline static std::map<std::string, std::string> helpStrings = {
        {
            "/readme", "config file system root dir\n\0"
        }, {
            "/Libary/art_config", "Android Runtime crash test help:\n wirte -h to the file start test\n\0"
        }
    };

    inline static std::map<std::string, uint64_t> lockset;

};


static int AppendCommSeparate(char **s, const char *append)
{
    int ret;
    char *news;
    size_t append_len, len;

    if (!append) {
        return 0;
    }

    append_len = strlen(append);
    if (!append_len) {
        return 0;
    }

    if (*s) {
        len = strlen(*s);
        news = (char*)realloc(*s, len + append_len + 2);
    } else {
        len = 0;
        news = (char*)realloc(NULL, append_len + 1);
    }
    if (!news) {
        return -ENOMEM;
    }

    if (*s) {
        ret = snprintf(news + len, append_len + 2, ",%s", append);
    } else {
        ret = snprintf(news, append_len + 1, "%s", append);
    }

    if (ret < 0) {
        return -EIO;
    }

    *s = news;
    return 0;
}

#if HAVE_FUSE3
static void *ConfigFsInit(struct fuse_conn_info *conn, struct fuse_config *cfg)
#else
static void *ConfigFsInit(struct fuse_conn_info *conn)
#endif
{

#if HAVE_FUSE3
    cfg->direct_io = 1;
    cfg->intr = 1;
#endif

    return fuse_get_context()->private_data;
}

static int ConfigFsOpen(const char *path, struct fuse_file_info *fi)
{
    return ConfigManager::GetInstance().Open(path, fi->lock_owner);
}

static int ConfigFsRead(const char *path, char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi)
{
    std::string str = ConfigManager::GetInstance().Read(path, fi->lock_owner).c_str();
    if (offset < str.length()) {
        if (offset + size > str.length()) {
            size = str.length() - offset;
        }
        memcpy(buf, str.c_str() + offset, size);
    } else {
        size = 0;
    }
    return size;
}

int ConfigFsWrite(const char *path, const char *buf, size_t size, off_t offset,
        struct fuse_file_info *fi)
{
    return ConfigManager::GetInstance().Write(path, fi->lock_owner, buf, size, offset);
}

static int ConfigFsRelease(const char *path, struct fuse_file_info *fi)
{
    return ConfigManager::GetInstance().Close(path, fi->lock_owner);;
}

#if HAVE_FUSE3
static int ConfigFsReadDir(const char *path, void *buf, fuse_fill_dir_t filler,
             off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
#else
static int ConfigFsReadDir(const char *path, void *buf, fuse_fill_dir_t filler,
             off_t offset, struct fuse_file_info *fi)
#endif
{
    int ret = 0;
    std::set<std::string> filelist;
    ret = ConfigManager::GetInstance().ReadDir(path, fi->lock_owner, filelist);
    if (ret == -1) {
        return -ENOENT;
    }
#ifdef HAVE_FUSE3
    filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
    filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
    for (auto s : filelist) {
        filler(buf, s.c_str(), NULL, 0, FUSE_FILL_DIR_PLUS);
    }
#else
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    for (auto s : filelist) {
        filler(buf, s.c_str(), NULL, 0);
    }
#endif
    return 0;
}

#if HAVE_FUSE3
static int ConfigFsGetattr(const char *path, struct stat *sb, struct fuse_file_info *fi)
#else
static int ConfigFsGetattr(const char *path, struct stat *sb)
#endif
{
    memset(sb, 0, sizeof(struct stat));
    int s = ConfigManager::GetInstance().GetFileType(path);
    if (s == 0) {
        return -ENOENT;
    }
    sb->st_mode = 0777 | s;

    return 0;
}

const static struct fuse_operations configfsOps = {
    .init = ConfigFsInit,
    .destroy = NULL,
    .open = ConfigFsOpen,
    .read = ConfigFsRead,
    .write = ConfigFsWrite,
    .release = ConfigFsRelease,
    .readdir = ConfigFsReadDir,
    .getattr = ConfigFsGetattr,
};

struct ConfigFsOpts {
    bool swap_off;
    bool use_pidfd;
    bool use_cfs;
    /*
     * Ideally we'd version by size but because of backwards compatability
     * and the use of bool instead of explicited __u32 and __u64 we can't.
     */
    __u32 version;
};

int configfs_loop(char* argv[]) {
    bool debug = false;
    char *new_fuse_opts = NULL;
    struct ConfigFsOpts *opts;
    opts = (struct ConfigFsOpts*)malloc(sizeof(struct ConfigFsOpts));
    if (opts == nullptr) {
        LogE("Allocate memory to opts failed!");
        return -1;
    }

    opts->swap_off = false;
    opts->use_pidfd = false;
    opts->use_cfs = false;
    opts->version = 1;

    int fuse_argc = 0;
    // rebuild fuse_main needed parameters
    char *fuse_argv[7];
    fuse_argv[fuse_argc++] = argv[0];

    if (debug) {
        // set enable debug
        fuse_argv[fuse_argc++] = "-d";
    } else {
        // foreground operation
        fuse_argv[fuse_argc++] = "-f";
    }

    fuse_argv[fuse_argc++] = "-o";

    // set mount option
    if (AppendCommSeparate(&new_fuse_opts, "allow_other")) {
        LogE("Failed to copy fuse argument \"allow_other\"");
        return -1;
    }

    // create mount point
    mkdir(MOUNT_POINT, 0777);
    
    fuse_argv[fuse_argc++] = new_fuse_opts;
    // set mount point for fuse
    fuse_argv[fuse_argc++] = MOUNT_POINT;
    fuse_argv[fuse_argc] = NULL;

    if (fuse_main(fuse_argc, fuse_argv, &configfsOps, opts)) {
        LogE("Fuse run abnormal: %s", strerror(errno));
        return -1;
    } else {
        return 0;
    }

    return 0;
}
