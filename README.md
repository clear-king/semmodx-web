# SemModX Web

**在浏览器里使用 SemModX 的「函数聚类 / Object Files」窗口，不需要打开 IDA 桌面端。**

SemModX Web 用 IDA Pro 9 自带的 **idalib**（IDA as a library）在后台无界面运行 IDA，
加载 [SemModX](https://github.com/clear-king/SemModX-) 插件的聚类与大模型分析代码，并通过一个本地网页提供：

- **模块树**：LFA 聚类得到的模块，以及每个模块里的函数（对应插件的 Object Files 窗口）
- **伪代码**：点击函数查看 Hex-Rays 反编译结果
- **分析模块**：按调用图逆序逐个函数送大模型分析，结果写回数据库注释，并生成模块总结
- **联合重命名**：对一个模块的函数统一建议变量名，默认只预演，勾选「实际写入」才会修改数据库
- **模块报告**：查看已写入数据库的模块分析报告
- **上传二进制**：上传 exe / dll / elf 等文件作为新的分析对象（也可以直接拖到页面上）

```
浏览器 ──HTTP/SSE──> FastAPI (serve.py) ──JSON 行协议──> IDA worker 子进程 (idalib, 无界面)
                                                            └── import semmodx（插件本体）
```

大模型请求走的是**插件自己的模型层**，所以插件 `config.ini` 里配置的任何供应商
（OpenAI、Anthropic、DeepSeek、Ollama、自定义 OpenAI 兼容接口）在网页端都能直接用，
两边的配置只需维护一份。

---

## 前置条件

| 项目 | 说明 |
|---|---|
| IDA Pro 9.x | 需要带 idalib（安装目录里有 `idalib.dll` / `libidalib.so`），并至少启动过一次 IDA 接受许可 |
| SemModX 插件 | 已安装到 IDA 的 `plugins/` 目录，并且 `config.ini` 至少配置了一个模型 |
| Python | **必须是 IDA 绑定的那个解释器**（用 `idapyswitch` 查看），IDA 9.0 支持 3.8–3.12 |
| 反编译器 | 「分析模块」「联合重命名」「伪代码」需要对应架构的 Hex-Rays 授权；只看模块树不需要 |

---

## 安装

以下命令都用 **IDA 绑定的 Python** 执行。

### 1. 安装并激活 idalib

```bash
pip install "<IDA 安装目录>/idalib/python"
python "<IDA 安装目录>/idalib/python/py-activate-idalib.py" -d "<IDA 安装目录>"
```

激活后会生成 `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json`（Linux/macOS 为
`~/.idapro/ida-config.json`）。

### 2. 安装依赖

```bash
pip install -r requirements.txt                    # 本项目：fastapi、uvicorn、python-multipart
pip install -r <semmodx 插件>/requirements.txt     # 插件本身的依赖
```

### 3. 配置

```bash
cp settings.ini.example settings.ini
```

编辑 `settings.ini`，最少只需要改一项：

```ini
[ida]
install_dir = C:\Program Files\IDA Professional 9.0
```

其余选项见 `settings.ini.example` 里的注释：IDA 用的 Python 路径、插件位置
（默认 `<install_dir>/plugins`）、监听地址、端口（默认 6001）、上传目录、额外的数据库扫描目录等。

如果服务运行在虚拟机中，并通过 NAT 端口转发让主机访问它，需要让虚拟机内的服务监听
所有接口：

```ini
[server]
host = 0.0.0.0
port = 6001
```

然后将虚拟机的 TCP `6001` 转发到主机的 TCP `6001`，主机仍通过
`http://127.0.0.1:6001` 访问。`0.0.0.0` 只表示虚拟机内的监听地址，不是主机浏览器要访问的地址。

**所有路径都写在 `settings.ini` 里，代码里没有任何写死的路径，也不读环境变量。**
`settings.ini` 不存在或写错时，`serve.py` 会直接提示文件应该放在哪里、缺什么。

### 4. 启动

```bash
python serve.py          # Windows 也可以双击 start.bat
```

浏览器打开 <http://127.0.0.1:6001>。

启动时会先做一遍检查：IDA 目录、Python 路径、插件和它的 `config.ini`、idalib
是否已激活、Web 依赖是否齐全，有问题会逐条列出并退出。

---

## 使用

1. 顶部下拉框选择一个已有的 `.i64` / `.idb` 数据库，或点「上传二进制」。点「打开」。
   首次打开一个新二进制会跑完整的自动分析，可能需要几分钟。
2. 左侧出现模块树。点模块查看范围、大小、函数数量；点函数查看伪代码。
3. 选中模块后可以「分析模块」或「联合重命名」，进度和结果实时显示在右侧。
4. 结果以注释形式写进数据库，和插件在 IDA 里写的格式完全一样，所以之后用桌面 IDA
   打开同一个库也能看到。关闭时要保存的话调用 `/api/close?save=true`。

数据库下拉框里的来源：

- `workspace/` 目录（默认）里的数据库
- `settings.ini` 的 `database_dirs` 里列出的目录
- 上传的二进制（分析并保存过之后，会直接打开生成的 `.i64`，不再重新分析）

---

## 设计说明

这几点是让它在无界面下跑通所必需的，修改代码前请先读：

1. **idalib 是单线程的。** 所有 IDA 调用必须在初始化库的那个线程上执行。因此 IDA
   运行在一个独立的 worker 子进程里，是一个同步循环；Web 端用一把锁串行化所有请求。

2. **协议显式使用 UTF-8。** 中文 Windows 的控制台代码页是 GBK，如果按默认编码读写
   管道，中文分析结果会被悄悄损坏，`idc.set_func_cmt` 随后直接报错。worker 和
   父进程两端都强制 UTF-8。

3. **stdout 被重定向。** 插件代码会大量 `print()`（例如逐条打印调用图的边），
   会把协议冲散。worker 把真正的 stdout 复制一份专门用于协议，其余输出写进
   `logs/ida_worker.log`。

4. **`execute_sync` 被替换。** 插件的模型层通过 `ida_kernwin.execute_sync()` 把结果
   交回 IDA 的界面线程；idalib 没有界面线程，这个回调永远不会触发。worker 把它
   替换成直接调用。

5. **一次只能打开一个数据库。** 打开新库前会先关闭旧库。在 idalib 里直接打开第二个
   库会让整个进程崩溃。

6. **图计算库。** 优先使用 `snap-stanford`；如果没装，自动退回到内置的纯 Python
   实现（`semmodx_web/snap_shim.py`，只实现了插件用到的那十几个方法）。注意 PyPI 上
   有一个同名但无关的 `snap` 包，它也能 import 成功，但没有任何图 API，worker 会
   识别出这种情况。

---

## 安全

- 服务**默认只监听 127.0.0.1**，并且**没有任何身份验证**。网页能看到被分析二进制的
  全部内容，还能上传文件、修改数据库。如果把 `[server] host` 改成别的地址（虚拟机
  NAT 场景通常是 `0.0.0.0`），`serve.py` 会给出警告。使用 `0.0.0.0` 时请确认虚拟机
  防火墙和 NAT 规则没有把服务暴露给不受信任的网络。
- 上传的文件当作不可信输入处理：只保留扩展名，丢弃客户端提供的目录部分，存到
  `workspace/uploads/<时间戳>-<名字>/` 下，永远不会被执行或导入，只有 IDA 会读取它。
  有扩展名白名单（无扩展名的文件允许，因为 Linux 下的 ELF 通常没有扩展名），
  默认大小上限 2 GiB。

---

## 测试

先启动服务，再运行：

```bash
python tests/smoke_test.py                       # 打开库、建模块树、建调用图、分析一个函数（会发一次真实的模型请求）
python tests/upload_test.py <一个 IDA 能加载的二进制>   # 上传、拒绝、路径穿越、无扩展名、打开
```

---

## 已知限制

- 同一个数据库同时只能被一个进程打开（IDA 会加锁），桌面 IDA 打开着某个库时，
  网页端打不开同一个库，反之亦然。
- 处理器模块没有授权的二进制会加载失败（idalib 返回错误码 4），worker 日志里会写明
  是哪个处理器。
- 联合重命名目前只对局部变量生效。

---

## 许可

GPL-3.0，见 `LICENSE`。本项目与 SemModX 插件一样，部分内容源自其他 GPL 项目：

- 源文件字符串扫描（`ida_worker.py` 中的 `get_source_strings`、`SOURCE_FILES_REGEXP`）
  经由 SemModX 移植自 [IDAMagicStrings](https://github.com/joxeankoret/idamagicstrings)
  （Joxean Koret，源码头部声明 GPL-3.0）。
- 「分析模块」「联合重命名」的提示词移植自 SemModX 插件的 `ida/handlers.py`。

聚类算法本身（LFA）在插件里，本项目运行时导入，不包含其代码。
