#ifndef _LANGUAGE_H
#define _LANGUAGE_H
#include <string>
// 语言相关配置
namespace LanguageSupport {
    struct LangSupport {
        std::string Name;                 //编程语言名称
        std::string MainFile;             //待测程序源码文件
        const char *const CompileCmd[20]; //编译待评测程序的命令行
        const char *const RunCmd[20];     //运行待评测程序的命令行
        bool VMrunning;                   //该语言是否以虚拟机方式运行
    };
    const LangSupport CLang = {
            "c", "Main.c",
            {"gcc", "Main.c", "-o", "Main", "-Wall",
             "-lm", "--static", "-std=c11", "-DONLINE_JUDGE", "-w", NULL
            },
            {"./Main", NULL},
            false
    };
    const LangSupport CppLang = {
            "c++", "Main.cpp",
            {"g++", "Main.cpp", "-o", "Main", "-std=c++11",
             "-Wall", "-lm", "--static", "-DONLINE_JUDGE", "-w", NULL},
            {"./Main", NULL},
            false
    };
    const LangSupport JavaLang = {
            "java", "Main.java",
            {"javac", "-J-Xms128M", "-J-Xmx512M", "Main.java", NULL},
            {"java", "-Djava.security.manager", "-Xms128M", "-Xms512M", "-DONLINE_JUDGE=true", "Main", NULL},
            true
    };
};
LanguageSupport::LangSupport const *Langs[] =
        {
                &LanguageSupport::CLang,
                &LanguageSupport::CppLang,
                &LanguageSupport::JavaLang
        };
#endif
