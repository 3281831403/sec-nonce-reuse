sec-nonce-reuse
===============

题面
----

加密模块上线后审计发现同一把密钥下出现了重复的随机数，密文还有可比的重复片段：计数器用有符号整数，回绕后变负并与旧值重复；派生只用计数器不用密钥标识，不同密钥得到相同随机数；固定段长度等于整块长度，计数段被挤掉；登记使用用集合但只存随机数不存密钥标识，跨密钥误判为重复；重复检测只比较完整相等，不比较公共前缀，近似重用漏检；密文公共前缀比较用了异或求和，位置不同的相同字节也被算作重叠；策略校验不检查计数器宽度，三十二位计数器在高速下很快回绕；策略校验不检查固定段长度，过长的固定段使随机数熵不足；计数器状态在批量分配间复用，第二个密钥从第一个密钥的计数继续；登记使用不清理旧记录，长时间运行后内存无界增长。nonce/guard.py 是核心，tests/test_guard.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式
--------

在仓库根目录执行：

    python -m pytest tests -q

桩实现全部抛 NotImplementedError，所以当前应看到 15 failed 且没有 collection error。测试文件只读，不要修改。

字段表
------

    字段              内容
    ----              ----
    所属领域          安全
    子方向            漏洞检测与攻防
    任务类型          Bugfix
    语言/框架         Python 3, pytest
    环境可复现等级    无外部依赖

目录布局
--------

本仓库采用 src 布局，而不是平铺布局：

    sec-nonce-reuse/
      README.md
      pyproject.toml
      src/nonce/__init__.py
      src/nonce/guard.py
      tests/conftest.py
      tests/test_guard.py

tests/conftest.py 把仓库根的 src 目录插入 sys.path，测试直接导入 nonce.guard。tests 不可修改。nonce/guard.py 是唯一实现文件，恰好 8 个桩。
## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

