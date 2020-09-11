修改自[acm309/Judger](https://github.com/acm309/Judger) 和 [KIDx/Judger](https://github.com/KIDx/Judger)

- 删除了topcoder模式
- 不同语言单独配置运行时间参数，不采用Java2倍的做法，在应用层解决
- 不考虑OLE，输出不匹配统一为WA
- 去掉meta.json的处理
- 暂时不考虑spj，但先别删

文件包括：

- json.hpp：一个c++的json库
- logger.h： 日志处理
- language.h：不同语言的运行配置
- okcall.h/okcall_x64/okcall_x86：系统调用白名单
- judge.h：判题
- http.h：web服务
- main.cpp：主文件

判题接口的参数：

- 语言 0: C 1: C++ 2: Java
- 时间限制
- 内存限制
- uid(可以找到所有in和out数据)
- 是否需要spj
- spj文件的uid

{
    "lang": 1,
    "time":
    "mem":
    "uid":
    "spj":0,
    "spjuid":
}

返回值：

- 状态码
- 编译错误信息
- 时间
- 内存

在支持多组测试的基础上，将各组判题结果汇总之后以 JSON 格式输出到 `result.json`。

根据 `meta.json` 获取判题组信息，比如:

```json
{
  "testcases": [
    { "uuid": "a09b1fa7-dd25-4013-a06f-0a04fa857373" },
    { "uuid": "f5296bf8-3673-4d22-b5d3-a008aea202bd" }
  ]
}
```

这之中有两组测试数据。测试数据的名称必须与 uuid 对应，比如: `a09b1fa7-dd25-4013-a06f-0a04fa857373.in` 和 `a09b1fa7-dd25-4013-a06f-0a04fa857373.out` 对应 上例中的第一组测试数据的输入与输出。

输出结果的解构为:

```json
[
  {
    "memory": 2040,
    "result": 2,
    "time": 0,
    "uuid": "a09b1fa7-dd25-4013-a06f-0a04fa857373"
  },
  {
    "memory": 2040,
    "result": 2,
    "time": 0,
    "uuid": "f5296bf8-3673-4d22-b5d3-a008aea202bd"
  }
]
```

根据 uuid 得出测试代码在各组数据上的表现情况。

`result` 字段对应测试结果，相关常量定义在 `judge.h` 中:

```cpp
const int OJ_WAIT       = 0;    //Queue
const int OJ_RUN        = 1;    //RUN
const int OJ_AC         = 2;    //AC
const int OJ_PE         = 3;    //PE
const int OJ_TLE        = 4;    //TLE
const int OJ_MLE        = 5;    //MLE
const int OJ_WA         = 6;    //WA
const int OJ_OLE        = 7;    //OLE
const int OJ_CE         = 8;    //CE
const int OJ_RE_SEGV    = 9;    //SEG Violation
const int OJ_RE_FPU     = 10;   //float.../0
const int OJ_RE_ABRT    = 11;   //Abort
const int OJ_RE_UNKNOW  = 12;   //Unknow
const int OJ_RF         = 13;   //Restricted Function
const int OJ_SE         = 14;   //System Error
const int OJ_RE_JAVA    = 15;   //Java Run Time Exception
```

## 使用

依赖:

```bash
apt-get install libcairo2-dev libjpeg8-dev libpango1.0-dev libgif-dev build-essential
```

配置:

对 `config.ini` 配置，其中将 `sysuser=root` 改为当前你正在使用的用户。

make 编译:

```bash
make
```

编译成功后:

```bash
./Judge -l 2 -D ./testdata -d temp -t 200 -m 65535 -o 81920
```

-l 对应语言，相关常量定义在 `language.h` 中

```cpp
const int LANG_UNKNOWN  = 0;
const int LANG_C        = 1;
const int LANG_CPP      = 2;
const int LANG_JAVA     = 3;
```

-D 指明测试数据的文件夹，里面包含了各组测试数据，如 `a09b1fa7-dd25-4013-a06f-0a04fa857373.in` 和 `a09b1fa7-dd25-4013-a06f-0a04fa857373.out`。

-d 指明临时文件夹，这个文件夹包含了 `ce.txt` (编译错误的信息，如果为空则为没有错误), `result.json` 测试结果，`Main.cpp` / `Main.c` / `Main.java` 测试代码。

-t 时间限制 允许程序运行的最长时间, 以毫秒为单位, 默认为1000, 1s

-m 内存限制 允许程序使用的最大内存量, 以KB为单位, 默认为65536, 64MB

-o 输出限制 允许程序输出的最大数据量, 以KB为单位, 默认为81920, 80MB

# 注意事项

1. config.ini 必须和编译后的 Judge 放在同一个文件夹内
2. `test.cpp` 790 行左右，删除了对 Java 安全性的检查，因此本评测机对 Java 语言的安全性把控可能达不到要求
