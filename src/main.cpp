/*
 * A simple and simple judger
 * Author: Keane modified from https://github.com/acm309/Judger
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <cerrno>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <dirent.h>
#include "judge.h"
#include "okcall.h"
#include "json.hpp"
#include "http.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define CONNMAX 1000
static int listenfd, clients[CONNMAX];

static void error(char *);

static void startServer(const char *);

static void respond(int);

typedef struct {
    char *name, *value;
} header_t;
static header_t reqhdr[17] = {{"\0", "\0"}};
static int clientfd;

static char *buf;

void serve_forever(const char *PORT) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    int slot = 0;
    printf("Server started http://127.0.0.1:%s\n", PORT);
    for (int i = 0; i < CONNMAX; i++) {
        clients[i] = -1;
    }
    startServer(PORT);
    // Ignore SIGCHLD to avoid zombie threads
    // 如果把这个注释掉就正常了
//    signal(SIGCHLD, SIG_IGN);

    // ACCEPT connections
    while (1) {
        addrlen = sizeof(clientaddr);
        clients[slot] = accept(listenfd, (struct sockaddr *) &clientaddr, &addrlen);

        if (clients[slot] < 0) {
            perror("accept() error");
        } else {
            if (fork() == 0) {
                respond(slot);
                exit(0);
            }
        }

        while (clients[slot] != -1) slot = (slot + 1) % CONNMAX;
    }
}

void startServer(const char *port) {
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, port, &hints, &res) != 0) {
        perror("getaddrinfo() error");
        exit(1);
    }
    for (p = res; p != NULL; p = p->ai_next) {
        int option = 1;
        listenfd = socket(p->ai_family, p->ai_socktype, 0);
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
        if (listenfd == -1) {
            continue;
        }
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
    }
    if (p == NULL) {
        perror("socket() or bind()");
        exit(1);
    }
    freeaddrinfo(res);
    if (listen(listenfd, 1000000) != 0) {
        perror("listen() error");
        exit(1);
    }
}

char *request_header(const char *name) {
    header_t *h = reqhdr;
    while (h->name) {
        if (strcmp(h->name, name) == 0) return h->value;
        h++;
    }
    return NULL;
}

std::string data = "";

void respond(int n) {
    int rcvd;
    buf = (char *) malloc(65535);
    rcvd = recv(clients[n], buf, 65535, 0);
    if (rcvd < 0)    // receive error
        fprintf(stderr, ("recv() error\n"));
    else if (rcvd == 0)    // receive socket closed
        fprintf(stderr, "Client disconnected upexpectedly.\n");
    else    // message received
    {
        buf[rcvd] = '\0';

        method = strtok(buf, " \t\r\n");
        uri = strtok(NULL, " \t");
        prot = strtok(NULL, " \t\r\n");
        fprintf(stderr, "\x1b[32m + [%s] %s\x1b[0m\n", method, uri);

        if (qs = strchr(uri, '?')) {
            *qs++ = '\0'; //split URI
        } else {
            qs = uri - 1; //use an empty string
        }

        header_t *h = reqhdr;
        char *t, *t2;
        bool content = false;
        while (h < reqhdr + 16) {
            char *k, *v, *t;
            if (content) {
                k = strtok(NULL, "\r\n: \t");
                if (!k) break;
                v = strtok(NULL, "\r\n");
                while (*v && *v == ' ') v++;
                data = std::string(k, k + strlen(k));
                data += ": ";
                data += v;
            } else {
                k = strtok(NULL, "\r\n: \t");
                if (!k) break;
                v = strtok(NULL, "\r\n");
                while (*v && *v == ' ') v++;
            }
            h->name = k;
            h->value = v;
            h++;
            fprintf(stderr, "[H] %s: %s\n", k, v);
            t = v + 1 + strlen(v);
            if (t[1] == '\r' && t[2] == '\n') {
                content = true;
            }
        }
        t = strtok(NULL, "\r\n");
//        t++; // now the *t shall be the beginning of user payload
        t2 = request_header("Content-Length"); // and the related header if there is
        payload = t;
        payload_size = t2 ? atol(t2) : (rcvd - (t - buf));

        // bind clientfd to stdout, making it easier to write
        clientfd = clients[n];
        dup2(clientfd, STDOUT_FILENO);
        close(clientfd);

        // call router
        route();

        // tidy up
        fflush(stdout);
        shutdown(STDOUT_FILENO, SHUT_WR);
        close(STDOUT_FILENO);
    }

    //Closing SOCKET
    shutdown(clientfd, SHUT_RDWR);         //All further send and recieve operations are DISABLED...
    close(clientfd);
    clients[n] = -1;
}

#define Max(x, y) (x) > (y) ? (x) : (y)
#define is_space_char(a) ((a == ' ') || (a == '\t') || (a == '\n') || (a == '\r'))
using namespace std;
using json = nlohmann::json;

//#define JUDGE_DEBUG
extern int errno;

void output_result(int result, int memory_usage = 0, int time_usage = 0) {
    //OJ_SE发生时，传入本函数的time_usage即是EXIT错误号，取负数是为了强调和提醒
    //此时若memory_usage < 0则为errno，说明错误发生的原因，取负数是为了强调和提醒
    //在前台看到System Error时，Time一栏的数值取绝对值就是EXIT错误号，Memory一栏取绝对值则为errno
    //OJ_RF发生时，传入本函数的time_usage即是syscall号，取负数是为了强调和提醒
    //在前台看到Dangerous Code时，Time一栏的数值取绝对值就是Syscall号
    //Bugfix：之前版本评测过程中每处错误发生时一般会直接exit，导致前台status一直Running
    if (result == judge_conf::OJ_SE || result == judge_conf::OJ_RF) time_usage *= -1;
#ifdef JUDGE_DEBUG
    LOG_DEBUG("result: %d, %dKB %dms", result, memory_usage, time_usage);
#endif
    printf("xx %d %d %d\n", result, memory_usage, time_usage);
}

void timeout(int signo) {
    output_result(judge_conf::OJ_SE, 0, judge_conf::EXIT_TIMEOUT);
    if (signo == SIGALRM)
        exit(judge_conf::EXIT_TIMEOUT);
}

void compare_until_nonspace(int &c_std, int &c_usr, FILE *&fd_std, FILE *&fd_usr, int &ret) {
    while ((isspace(c_std)) || (isspace(c_usr))) {
        if (c_std != c_usr) {
            if (c_std == EOF || c_usr == EOF) {
                return;
            }
            if (c_std == '\r' && c_usr == '\n') {
                c_std = fgetc(fd_std);
                if (c_std != c_usr)
                    ret = judge_conf::OJ_PE;
            } else {
                ret = judge_conf::OJ_PE;
            }
        }
        if (isspace(c_std))
            c_std = fgetc(fd_std);
        if (isspace(c_usr))
            c_usr = fgetc(fd_usr);
    }
}

// 在spj_path里写一个spj.cpp printf("AC")就是AC，即可
int spj_compare_output(
        string input_file,  //标准输入文件
        string output_file, //用户程序的输出文件
        string spj_path,    //spj路径, change it from exefile to the folder who store the exefile
        string file_spj,    //spj的输出文件
        string output_file_std) {
    LOG_DEBUG("1 %s\n", (spj_path + "/" + problem::spj_exe_file).c_str());
    LOG_DEBUG("2 %s\n", problem::spj_exe_file.c_str());
    LOG_DEBUG("3 %s\n", input_file.c_str());
    LOG_DEBUG("4 %s\n", output_file.c_str());
    LOG_DEBUG("5 %s\n", output_file_std.c_str());
    LOG_DEBUG("6 %s\n", file_spj.c_str());
#ifdef JUDGE_DEBUG__
    cout<<"inputfile: "<<input_file<<endl;
    cout<<"outputfile: "<<output_file<<endl;
    cout<<"spj_exec: "<<spj_path<<endl;
    cout<<"file_spj: "<<file_spj<<endl;
#endif
    /*
    Improve: Auto rebuild spj.out while find spj.cpp
    Improve: If spj.out is not exist, return SE
    Date & Time: 2013-11-10 08:03
    Author: Sine
    */
    if (access((spj_path + "/spj.cpp").c_str(), 0) == 0) {
        string syscmd = "g++ -o ";
        syscmd += spj_path + "/" + problem::spj_exe_file + " " + spj_path + "/spj.cpp";
        LOG_DEBUG("%s\n", syscmd.c_str());
        system(syscmd.c_str());
        syscmd = "mv -f ";
        syscmd += spj_path + "/spj.cpp " + spj_path + "/spj.oldcode";
        system(syscmd.c_str());
    }
    if (access((spj_path + "/" + problem::spj_exe_file).c_str(), 0)) {
        output_result(judge_conf::OJ_SE, 0, judge_conf::EXIT_ACCESS_SPJ);
        exit(judge_conf::EXIT_ACCESS_SPJ);
    }
    //    return judge_conf::OJ_SE;
    //End of the Improve*/
    int status = 0;
    pid_t pid_spj = fork();
    if (pid_spj < 0) {
        LOG_WARNING("error for spj failed, %d:%s", errno, strerror(errno));
        output_result(judge_conf::OJ_SE, -errno, judge_conf::EXIT_COMPARE_SPJ_FORK);
        exit(judge_conf::EXIT_COMPARE_SPJ_FORK);
    } else if (pid_spj == 0) {
        freopen(file_spj.c_str(), "w", stdout);
        if (EXIT_SUCCESS == malarm(ITIMER_REAL, judge_conf::spj_time_limit)) {
            log_close();
            //argv[1] 标准输入 ， argv[2] 用户程序输出, argv[3] 标准输出
            if (execlp((spj_path + "/" + problem::spj_exe_file).c_str(),
                       problem::spj_exe_file.c_str(), input_file.c_str(),
                       output_file.c_str(), output_file_std.c_str(), NULL) < 0) {
                printf("spj execlp error\n");
            }
        }
    } else {
        // TODO no child process 找不出原因 注释掉
        if (waitpid(pid_spj, &status, 0) < 0) {
            LOG_BUG("waitpid failed, %d:%s", errno, strerror(errno));
            output_result(judge_conf::OJ_SE, -errno, judge_conf::EXIT_COMPARE_SPJ_WAIT);
            exit(judge_conf::EXIT_COMPARE_SPJ_WAIT);
        }
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == EXIT_SUCCESS) {
                FILE *fd = fopen(file_spj.c_str(), "r");
                if (fd == NULL) {
                    output_result(judge_conf::OJ_SE, 0, judge_conf::EXIT_COMPARE_SPJ_OUT);
                    exit(judge_conf::EXIT_COMPARE_SPJ_OUT);
                }
                char buf[20];
                if (fscanf(fd, "%19s", buf) == EOF) {
                    return judge_conf::OJ_WA;
                }
                fclose(fd);
                if (strcmp(buf, "AC") == 0) {
                    return judge_conf::OJ_AC;
                } else if (strcmp(buf, "PE") == 0) {
                    return judge_conf::OJ_PE;
                } else if (strcmp(buf, "WA") == 0) {
                    return judge_conf::OJ_WA;
                }
            }
        }
    }
    return judge_conf::OJ_WA;
}

int tt_compare_output(string &file_std, string &file_usr) {
    int ret = judge_conf::OJ_AC;
    int c_std, c_usr;
    FILE *fd_std = fopen(file_std.c_str(), "r");
    FILE *fd_usr = fopen(file_usr.c_str(), "r");
    if (fd_std == NULL) {
        LOG_BUG("%s open standard file failed %s", strerror(errno), file_std.c_str());
    }
    if (!fd_std || !fd_usr) {
        ret = judge_conf::OJ_RE_ABRT;
    } else {
        c_std = fgetc(fd_std);
        c_usr = fgetc(fd_usr);
        for (;;) {
            compare_until_nonspace(c_std, c_usr, fd_std, fd_usr, ret);
            while (!isspace(c_std) || !isspace(c_usr)) {
                if (c_std == EOF && c_usr == EOF)
                    goto end;
                // 如果只有一个文件结束
                // 但是另一个文件的末尾是回车
                // 那么也当做AC处理
                // https://github.com/NJUST-FishTeam/OnlineJudgeCore/blob/master/core.h
                if (c_std == EOF || c_usr == EOF) {
                    FILE *fd_tmp;
                    if (c_std == EOF) {
                        if (!is_space_char(c_usr)) {
                            ret = judge_conf::OJ_WA;
                            goto end;
                        }
                        fd_tmp = fd_usr;
                    } else {
                        if (!is_space_char(c_std)) {
                            ret = judge_conf::OJ_WA;
                            goto end;
                        }
                        fd_tmp = fd_std;
                    }
                    int c;
                    while ((c = fgetc(fd_tmp)) != EOF) {
                        if (c == '\r') c = '\n';
                        if (!is_space_char(c)) {
                            ret = judge_conf::OJ_WA;
                            goto end;
                        }
                    }
                    goto end;
                }
                if (c_std != c_usr) {
                    ret = judge_conf::OJ_WA;
                    goto end;
                }
                c_std = fgetc(fd_std);
                c_usr = fgetc(fd_usr);
            }
        }
    }
    end:
    if (fd_std)
        fclose(fd_std);
    if (fd_usr)
        fclose(fd_usr);
    return ret;
}

int compare_output(string &file_std, string &file_usr) {
    return tt_compare_output(file_std, file_usr);
}

void io_redirect() {
    freopen(problem::input_file.c_str(), "r", stdin);
    freopen(problem::output_file.c_str(), "w", stdout);
    freopen(problem::output_file.c_str(), "w", stderr);
    if (stdin == NULL || stdout == NULL) {
        LOG_BUG("error in freopen: stdin(%p) stdout(%p)", stdin, stdout);
        exit(judge_conf::EXIT_PRE_JUDGE);
    }
#ifdef JUDGE_DEBUG
    LOG_DEBUG("io redirece ok!");
#endif
}

void set_limit() {
    rlimit lim;
    //时间限制
    lim.rlim_cur = (problem::time_limit + 999) / 1000 + 1;
    lim.rlim_max = lim.rlim_cur * 10;
    if (setrlimit(RLIMIT_CPU, &lim) < 0) {
        LOG_BUG("error setrlimit for rlimit_cpu");
        exit(judge_conf::EXIT_SET_LIMIT);
    }
    //设置堆栈的大小，漏掉主程序会SIGSEGV
    getrlimit(RLIMIT_STACK, &lim);
    int rlim = judge_conf::stack_size_limit * judge_conf::KILO;
    //LOG_DEBUG("set stack size : %d", rlim);
    if (lim.rlim_max <= rlim) {
        LOG_WARNING("can't set stack size to higher(%d <= %d)", lim.rlim_max, rlim);
    } else {
        lim.rlim_max = rlim;
        lim.rlim_cur = rlim;
        if (setrlimit(RLIMIT_STACK, &lim) < 0) {
            LOG_WARNING("setrlimit RLIMIT_STACK failed: %s", strerror(errno));
            exit(judge_conf::EXIT_SET_LIMIT);
        }
    }
    log_close();
}

int Compiler() {
    int status = 0;
    pid_t compiler = fork();
    if (compiler < 0) {
        LOG_WARNING("error fork compiler, %d:%s", errno, strerror(errno));
        output_result(judge_conf::OJ_SE, -errno, judge_conf::EXIT_COMPILE);
        exit(judge_conf::EXIT_COMPILE);
    } else if (compiler == 0) {
        chdir(judge_conf::temp_dir.c_str());
        freopen("./ce.txt", "w", stderr); //编译出错信息
        freopen("/dev/null", "w", stdout); //防止编译器在标准输出中输出额外的信息影响评测
        malarm(ITIMER_REAL, judge_conf::compile_time_limit);
        execvp(Langs[problem::lang]->CompileCmd[0], (char *const *) Langs[problem::lang]->CompileCmd);
        //execvp    error
        LOG_WARNING("compile evecvp error");
        exit(judge_conf::EXIT_COMPILE);
    } else {
        waitpid(compiler, &status, 0);
        return status;
    }
}

const int bufsize = 1024;

int getmemory(pid_t userexe) {
    int ret = 0;
    FILE *pd;
    char fn[bufsize], buf[bufsize];
    sprintf(fn, "/proc/%d/status", userexe);
    pd = fopen(fn, "r");
    while (pd && fgets(buf, bufsize - 1, pd))    //这里漏掉了pd & 导致主进程SIGSEGV
    {
        if (strncmp(buf, "VmPeak:", 7) == 0) {
            sscanf(buf + 8, "%d", &ret);
        }
    }
    if (pd) fclose(pd);
    return ret;
}

void sigseg(int) {
    output_result(judge_conf::OJ_SE, 0, judge_conf::EXIT_UNPRIVILEGED);
    exit(judge_conf::EXIT_UNPRIVILEGED);
}

// 自己重新封装判题逻辑，方便web服务调用
// sid：提交id
// lang：语言 0[C] 1[C++] 2[Java]
// uid：数据和spj所在文件夹
// num：测试数据数量
// time：时间限制，单位ms
// mem：内存限制，单位KB
// spj：是否需要spj，0[否] 1[是]
json judge(string sid, int lang, string uuid, int num, int time, int mem, int spj) {
    // parse参数
    problem::lang = lang;
    problem::time_limit = time;
    problem::memory_limit = mem;
    problem::spj = spj;
    if (problem::spj) {
        problem::spj_exe_file = "spj.out";
        problem::stdout_file_spj = "stdout_spj.txt";
    }
    // 为何是+=?
    judge_conf::judge_time_limit += problem::time_limit;
    // 设置judge运行时限(默认最多跑30s)
    if (EXIT_SUCCESS != malarm(ITIMER_REAL, judge_conf::judge_time_limit)) {
        LOG_WARNING("set judge alarm failed, %d : %s", errno, strerror(errno));
        output_result(judge_conf::OJ_SE, 0, judge_conf::EXIT_VERY_FIRST);
        exit(judge_conf::EXIT_VERY_FIRST);
    }
    signal(SIGALRM, timeout);
    // 编译
    int compile_ok = Compiler();
    // CE
    if (compile_ok != 0) {
        output_result(judge_conf::OJ_CE);
        exit(judge_conf::EXIT_OK);
    }
    json result = json::array();
    string testdata_dir = judge_conf::work_dir + "/TestCase/" + uuid;
    // 运行
    DIR *dp;
    dp = opendir(testdata_dir.c_str());
    if (dp == NULL) {
        LOG_WARNING("error opening dir %s", testdata_dir.c_str());
        output_result(judge_conf::OJ_SE, 0, judge_conf::EXIT_PRE_JUDGE);
        exit(judge_conf::EXIT_PRE_JUDGE);
    }
    for (int i = 1; i <= num; i++) {
        struct rusage rused;
        problem::input_file = testdata_dir + "/" + to_string(i) + ".in";
        problem::output_file_std = testdata_dir + "/" + to_string(i) + +".out";
        problem::output_file = judge_conf::temp_dir + "/" + to_string(i) + ".out";

        pid_t userexe = fork();
        if (userexe < 0) {
            LOG_WARNING("fork failed, %d:%s", errno, strerror(errno));
            output_result(judge_conf::OJ_SE, -errno, judge_conf::EXIT_PRE_JUDGE);
            exit(judge_conf::EXIT_PRE_JUDGE);
        } else if (userexe == 0) {
            signal(SIGSEGV, sigseg);
            for (int i = 0; i < 6; i++) {
                LOG_DEBUG("%s ", Langs[problem::lang]->RunCmd[i]);
            }
            //重新定向io
            io_redirect();
            //获得运行用户的信息
            struct passwd *judge = getpwnam(judge_conf::sysuser.c_str());
            if (judge == NULL) {
                LOG_BUG("no user named %s", judge_conf::sysuser.c_str());
                exit(judge_conf::EXIT_SET_SECURITY);
            }
            //切换目录
            if (EXIT_SUCCESS != chdir(judge_conf::temp_dir.c_str())) {
                LOG_BUG("chdir failed");
                exit(judge_conf::EXIT_SET_SECURITY);
            }
            //设置有效用户
            if (EXIT_SUCCESS != setuid(judge->pw_uid)) {
                LOG_BUG("setuid failed");
                exit(judge_conf::EXIT_SET_SECURITY);
            }
            int user_time_limit = problem::time_limit + judge_conf::time_limit_addtion;
            // 设置用户程序的运行实际时间，防止意外情况卡住
            if (EXIT_SUCCESS != malarm(ITIMER_REAL, user_time_limit)) {
                LOG_WARNING("malarm failed");
                exit(judge_conf::EXIT_PRE_JUDGE);
            }
            // ptrace 监控下面程序
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
                LOG_BUG("ptrace failed");
                exit(judge_conf::EXIT_PRE_JUDGE_PTRACE);
            }
            // 设置用户程序的 内存 时间的限制
            set_limit();
            // 运行程序，正常运行则没有返回值
            execvp(Langs[problem::lang]->RunCmd[0], (char *const *) Langs[problem::lang]->RunCmd);
            int errsa = errno;
            exit(judge_conf::EXIT_PRE_JUDGE_EXECLP);
        } else {
            // 父进程监控子进程的状态和系统调用
            int status = 0;
            int syscall_id = 0;
            struct user_regs_struct regs;
            init_ok_table(problem::lang);
            while (true) {
                if (wait4(userexe, &status, 0, &rused) < 0) {
                    LOG_BUG("wait4 failed, %d:%s", errno, strerror(errno));
                    output_result(judge_conf::OJ_SE, -errno, judge_conf::EXIT_JUDGE);
                    exit(judge_conf::EXIT_JUDGE);
                }
                // 如果是退出信号
                if (WIFEXITED(status)) {
                    LOG_DEBUG("%d\n", WEXITSTATUS(status));
                    // java 返回非0表示出错
                    if (!Langs[problem::lang]->VMrunning || WEXITSTATUS(status) == EXIT_SUCCESS) {
                        int result;
                        if (problem::spj) {
                            //spj
                            result = spj_compare_output(problem::input_file,
                                                        problem::output_file,
                                                        testdata_dir, //problem::spj_exe_file, modif y in 13-11-10
                                                        judge_conf::temp_dir + "/" + problem::stdout_file_spj,
                                                        problem::output_file_std);
                        } else {
                            result = compare_output(problem::output_file_std, problem::output_file);
                        }
                        //记录结果？？
                        if (result != judge_conf::OJ_AC) {
                            problem::result = result;
                        } else if (problem::result != judge_conf::OJ_PE) {
                            problem::result = result;
                        }
                    } else {
                        LOG_BUG("abort quit code: %d\n", WEXITSTATUS(status));
                        problem::result = judge_conf::OJ_RE_JAVA;
                    }
                    break;
                }
                // 收到信号
                // 超过sterlimit限制而结束
                // 且过滤掉被ptrace暂停的 SIGTRAP
                if (WIFSIGNALED(status) || (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP)) {
                    int signo = 0;
                    if (WIFSIGNALED(status)) {
                        signo = WTERMSIG(status);
                    } else {
                        signo = WSTOPSIG(status);
                    }
                    switch (signo) {
                        case SIGKILL:
                            problem::result = judge_conf::OJ_TLE;
                            problem::time_usage = problem::time_limit;
                            break;
                        case SIGSEGV:
                            problem::result = judge_conf::OJ_RE_SEGV;
                            break;
                        case SIGABRT:
                            problem::result = judge_conf::OJ_RE_ABRT;
                            break;
                        default:
                            problem::result = judge_conf::OJ_RE_UNKNOW;
                    }
                    ptrace(PTRACE_KILL, userexe);
                    break;
                }
                int tempmemory = 0;
                if (Langs[problem::lang]->VMrunning) {
                    tempmemory = rused.ru_minflt * (getpagesize() / judge_conf::KILO);
                } else {
                    tempmemory = getmemory(userexe);
                }
                problem::memory_usage = Max(problem::memory_usage, tempmemory);
                if (problem::memory_usage > problem::memory_limit) {
                    problem::result = judge_conf::OJ_MLE;
                    ptrace(PTRACE_KILL, userexe);
                    break;
                }
                // 检查userexe的syscall
                if (ptrace(PTRACE_GETREGS, userexe, 0, &regs) < 0) {
                    LOG_BUG("error ptrace ptrace_getregs, %d:%s", errno, strerror(errno));
                    output_result(judge_conf::OJ_SE, -errno, judge_conf::EXIT_JUDGE);
                    exit(judge_conf::EXIT_JUDGE);
                }
#ifdef __i386__
                syscall_id = regs.orig_eax;
#else
                syscall_id = regs.orig_rax;
#endif
                // 取消对 Java 安全性检查，否则该评测机不能正常运行
                if (judge_conf::LANG_JAVA != problem::lang && syscall_id > 0 &&
                    (!is_valid_syscall(problem::lang, syscall_id, userexe, regs))) {
                    LOG_WARNING("error for syscall %d", syscall_id);
                    problem::result = judge_conf::OJ_RF;
                    problem::time_usage = syscall_id;
                    ptrace(PTRACE_KILL, userexe, NULL, NULL);
                    break;
                }
                if (ptrace(PTRACE_SYSCALL, userexe, NULL, NULL) < 0) {
                    LOG_BUG("error ptrace ptrace syscall, %d:%s", errno, strerror(errno));
                    output_result(judge_conf::OJ_SE, -errno, judge_conf::EXIT_JUDGE);
                    exit(judge_conf::EXIT_JUDGE);
                }
            }
        }
        int time_tmp = rused.ru_utime.tv_sec * 1000 + rused.ru_utime.tv_usec / 1000
                       + rused.ru_stime.tv_sec * 1000 + rused.ru_stime.tv_usec / 1000;
        if (problem::time_usage < time_tmp) {
            problem::time_usage = time_tmp;
        }
        if (problem::time_usage > problem::time_limit) {
            problem::time_usage = problem::time_limit;
            problem::result = judge_conf::OJ_TLE;
        }
        if (problem::memory_usage > problem::memory_limit) {
            problem::memory_usage = problem::memory_limit;
            problem::result = judge_conf::OJ_MLE;
        }
        json j = json::object();
        j["uuid"] = uuid + "-" + to_string(i);
        j["result"] = problem::result;
        j["time"] = problem::time_usage;
        j["memory"] = problem::memory_usage;
        result.push_back(j);
    }
    return result;
}

void route() {
    ROUTE_START()
    ROUTE_POST("/judge")
        {
            printf("HTTP/1.1 200 OK\r\n\r\n");
            printf("%s\n", data.c_str());
            auto req = json::parse(data);
            string sid = req["sid"].get<string>();
            int lang = req["lang"].get<int>();
            string uuid = req["uuid"].get<string>();
            int num = req["num"].get<int>();
            int time = req["time"].get<int>();
            int mem = req["mem"].get<int>();
            int spj = req["spj"].get<int>();
            json result = judge(sid, lang, uuid, num, time, mem, spj);
            printf("%s\n", result.dump().c_str());
        }
        ROUTE_END()
}

int main() {
    // 读config.ini配置文件
    judge_conf::ReadConf();
    // 打开日志文件
    log_open(judge_conf::log_file.c_str());
    // 启动web服务
    serve_forever("12913");
//    json result = judge("a09b1fa7-dd25-4013-a06f-0a04fa857374", 2, "a09b1fa7-dd25-4013-a06f-0a04fa857373", 3, 1000,32768, 0);
//    printf("%s\n", result.dump().c_str());
    return 0;
}
