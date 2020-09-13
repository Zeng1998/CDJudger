修改自[acm309/Judger](https://github.com/acm309/Judger) 和 [KIDx/Judger](https://github.com/KIDx/Judger)

- 删除了topcoder模式
- 不同语言单独配置运行时间参数，不采用Java2倍的做法，在应用层解决
- 不考虑OLE，输出不匹配统一为WA
- 去掉meta.json的处理

TODO:

- 修改运行时temp文件夹位置

文件包括：

- json.hpp：一个c++的json库
- logger.h： 日志处理
- language.h：不同语言的运行配置
- okcall.h/okcall_x64/okcall_x86：系统调用白名单
- judge.h：判题
- http.h：web服务
- main.cpp：主文件

判题接口的参数：

- sid：提交id
- lang：语言 0(C) 1(C++) 2(Java)
- uid：数据和spj所在文件夹
- num：测试数据数量
- time：时间限制，单位ms
- mem：内存限制，单位KB
- spj：是否需要spj，0(否) 1(是)

返回值：
多组测试数据单独的judge结果

- 提交id(如果考虑把判题结果也放一个队列里)
- 测试数据uuid-编号
- 状态码
- 编译错误信息
- 时间
- 内存

## 使用

依赖:

```bash
apt-get install libcairo2-dev libjpeg8-dev libpango1.0-dev libgif-dev build-essential
```

配置:

对 `config.ini` 配置，其中将 `sysuser` 改为当前你正在使用的用户。

cmake编译:

```bash
cmake . && make
```

编译成功后(可能需要`sudo`):

```bash
./CDJudge
```


> [本评测机对 Java 语言的安全性把控可能达不到要求](https://github.com/acm309/Judger)
