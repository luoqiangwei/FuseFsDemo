
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
#include <map>
#include <mutex>
#include <vector>
#include <fstream>

std::vector<std::string> Split(const std::string &s, const std::string& c) {
    std::vector<std::string> tokens;
    std::string t = s;
    size_t pos = 0;
    std::string token;
    while ((pos = t.find(c)) != std::string::npos) {
        token = t.substr(0, pos);
        tokens.push_back(token);
        t.erase(0, pos + c.length());
    }
    if(t.length() > 0) {
        tokens.push_back(t);
    }
    return tokens;
}

typedef struct ConfigFsFile File;
typedef struct ConfigFsDir Dir;

struct ConfigFsFile {
    std::string filename;
    Dir* parent;
    std::vector<std::string> context;
};

struct ConfigFsDir {
    std::string dirname;
    Dir* parent;
    std::map<std::string, File> fileContext;
    std::map<std::string, Dir> dirContext;
};


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

    // Parsing configfs.txt and creating a file system structure
    bool Init() {
        rootDir.dirname = "/";
        rootDir.parent = nullptr;
        dirIndex["/"] = &rootDir;
        std::ifstream inFile;
        inFile.open("configfs.txt");
        if (!inFile) {
            LogE("Must need configfs.txt");
            return false;
        }

        std::string readLine;
        std::string content;
        std::string tmpPath;
        Dir *tmpDir = &rootDir;
        File tmepFile = {};
        while (std::getline(inFile, readLine)) {
            tmpDir = &rootDir;
            tmpPath = "/";
            LogI("Parse config line: %s", readLine.c_str());
            // Skip comment
            if (readLine.at(0) == '#') {
                continue;
            // Parse file path
            } else if (readLine.at(0) == '/') {
                std::vector<std::string> pathAndContext = Split(readLine, ":");
                content = "";
                for (size_t i = 1; i < pathAndContext.size(); i++) {
                    content += pathAndContext[i];
                    if (i < pathAndContext.size() - 1) {
                        content += ":";
                    }
                }
                std::vector<std::string> paths = Split(pathAndContext[0], "/");
                for (size_t i = 0; i < paths.size(); i++) {
                    if (paths[i] == "") continue;
                    if (i == paths.size() - 1) {
                        tmpPath += paths[i];
                        // Create a new file struct
                        tmepFile.parent = tmpDir;
                        tmepFile.filename = paths[i];
                        tmepFile.context = Split(content, "\\n");
                        // Add to dir
                        tmpDir->fileContext[paths[i]] = tmepFile;
                        // Build index
                        fileIndex[tmpPath] = &tmpDir->fileContext[paths[i]];
                        LogI("Add file: %s", tmpPath.c_str());
                        break;
                    }
                    tmpPath += paths[i];
                    // Auto fill dir context
                    if (tmpDir->dirContext.find(paths[i]) == tmpDir->dirContext.end()) {
                        tmpDir->dirContext[paths[i]].dirname = paths[i];
                        tmpDir->dirContext[paths[i]].parent = tmpDir;
                        LogI("Add dir: %s", tmpPath.c_str());
                    }
                    dirIndex[tmpPath] = &tmpDir->dirContext[paths[i]];
                    tmpDir = &tmpDir->dirContext[paths[i]];
                    tmpPath += "/";
                }
            }
        }

        return true;
    }

    File* FindFile(const std::string& p) {
        // find index
        if (fileIndex.find(p) != fileIndex.end()) {
            LogD("Hit file cache");
            return fileIndex[p];
        }
        Dir *tmpDir = &rootDir;
        // find file system tree
        std::vector<std::string> paths = Split(p, "/");
        for (size_t i = 0; i < paths.size(); i++) {
            if (i == paths.size() - 1) {
                if (tmpDir->fileContext.find(paths[i]) != tmpDir->fileContext.end()) {
                    return &tmpDir->fileContext[paths[i]];
                }
                break;
            }
            if (tmpDir->dirContext.find(paths[i]) != tmpDir->dirContext.end()) {
                tmpDir = &tmpDir->dirContext[paths[i]];
            } else {
                break;
            }
        }
        return nullptr;
    }

    Dir* FindDir(const std::string& p) {
        // find index
        if (dirIndex.find(p) != dirIndex.end()) {
            LogD("Hit dir cache");
            return dirIndex[p];
        }
        Dir *tmpDir = &rootDir;
        // find file system tree
        std::vector<std::string> paths = Split(p, "/");
        for (size_t i = 0; i < paths.size(); i++) {
            if (i == paths.size() - 1) {
                if (tmpDir->dirContext.find(paths[i]) != tmpDir->dirContext.end()) {
                    return &tmpDir->dirContext[paths[i]];
                }
                break;
            }
            if (tmpDir->dirContext.find(paths[i]) != tmpDir->dirContext.end()) {
                tmpDir = &tmpDir->dirContext[paths[i]];
            } else {
                break;
            }
        }
        return nullptr;
    }

    int Open(const char *path, uint64_t lockOwner) {
        std::string p(path);
        errno = 0;
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
        std::string retStr = "";
        File *f = FindFile(p);
        if (f == nullptr) {
            retStr += "No such file!\n";
        } else {
            for (auto s : f->context) {
                retStr += s + "\n";
            }
        }
        return retStr;
    }

    int Write(const char *path, uint64_t lockOwner, const char* buf, size_t size, off_t offset) {
        std::string p(path);
        errno = 0;
        if (!checkPermissions(path, lockOwner)) {
            errno = EPERM;
            return -1;
        }
        if (FindFile(p) == nullptr) {
            errno = ENOENT;
            return -1;
        }
        // *******************************************
        // *** TODO: parse buf and control inhook test
        // *** TIPS: use looper handler request (reduce the filesystem time use)
        // *******************************************
        LogI("Recv data: %s\n", buf);
        return size;
    }

    int ReadDir(const char *path, uint64_t lockOwner, std::vector<std::string>& list) {
        LogW("[ReadDir]Read dir: %s", path);
        std::string p(path);
        errno = 0;
        if (!checkPermissions(path, lockOwner)) {
            errno = EPERM;
            return -1;
        }
        Dir* d = FindDir(p);
        if (d != nullptr) {
            // Append files
            for (auto s : d->fileContext) {
                list.push_back(s.first);
            }
            // Append dirs
            for (auto s : d->dirContext) {
                list.push_back(s.first);
            }
        }
        return 0;
    }

    int GetFileType(const char *path) {
        // Determine file type
        std::string p(path);
        if (FindDir(p) != nullptr) {
            return S_IFDIR;
        } else if (FindFile(p) != nullptr) {
            return S_IFREG;
        }
        return 0;
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

    // config fs root node
    inline static Dir rootDir;
    inline static std::map<std::string, Dir*> dirIndex;
    inline static std::map<std::string, File*> fileIndex;
    inline static std::map<std::string, uint64_t> lockset;

};


static int AppendCommSeparate(char **s, const char *append) {
	int ret;
	char *news;
	size_t append_len, len;

	if (!append)
		return 0;

	append_len = strlen(append);
	if (!append_len)
		return 0;

	if (*s) {
		len = strlen(*s);
		news = (char*)realloc(*s, len + append_len + 2);
	} else {
		len = 0;
		news = (char*)realloc(NULL, append_len + 1);
	}
	if (!news)
		return -ENOMEM;

	if (*s)
		ret = snprintf(news + len, append_len + 2, ",%s", append);
	else
		ret = snprintf(news, append_len + 1, "%s", append);
	if (ret < 0)
		return -EIO;

	*s = news;
	return 0;
}

#if HAVE_FUSE3
static void *ConfigFsInit(struct fuse_conn_info *conn, struct fuse_config *cfg) {
#else
static void *ConfigFsInit(struct fuse_conn_info *conn) {
#endif

#if HAVE_FUSE3
	cfg->direct_io = 1;
	cfg->intr = 1;
#endif

	return fuse_get_context()->private_data;
}

static int ConfigFsOpen(const char *path, struct fuse_file_info *fi) {
	return ConfigManager::GetInstance().Open(path, fi->lock_owner);
}

static int ConfigFsRead(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi) {
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
		struct fuse_file_info *fi) {
	return ConfigManager::GetInstance().Write(path, fi->lock_owner, buf, size, offset);
}

static int ConfigFsRelease(const char *path, struct fuse_file_info *fi) {
	return ConfigManager::GetInstance().Close(path, fi->lock_owner);;
}

#if HAVE_FUSE3
static int ConfigFsReadDir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
#else
static int ConfigFsReadDir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi) {
#endif
    int ret = 0;
    std::vector<std::string> filelist;
    // Get directory structure from ConfigManager
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
static int ConfigFsGetattr(const char *path, struct stat *sb, struct fuse_file_info *fi) {
#else
static int ConfigFsGetattr(const char *path, struct stat *sb) {
#endif
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

    if (!ConfigManager::GetInstance().Init()) {
        return -1;
    }

    if (fuse_main(fuse_argc, fuse_argv, &configfsOps, opts)) {
        LogE("Fuse run abnormal: %s", strerror(errno));
        return -1;
    } else {
        return 0;
    }

    return 0;
}
