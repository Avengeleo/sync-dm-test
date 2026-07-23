# sync-dm-test · IM 后端自测工作区

一个 PyCharm 项目容纳**多个服务的独立测试套件**,不依赖前端,直打 HTTP。
打开 **`sync-dm-test` 这个文件夹**为项目根即可分别测各服务。

## 结构

```
sync-dm-test/                 ← 打开这个为 PyCharm 项目根
├── pytest.ini                # 统一配置:pythonpath、testpaths、markers
├── conftest.py               # 根:加载 .env + 注册 markers + 按目录自动打服务标记
├── requirements.txt          # 共享依赖(pytest/requests/python-dotenv)
├── .env.example / .env       # 一个文件管全部服务,按前缀区分(BI_* / DM_API_*)
├── common/                   # 跨服务共享库
│   ├── http_client.py        #   BaseClient + Envelope(bi/dm 信封同构,复用)
│   └── assets.py             #   纯 Python 造 PNG/ZIP(不依赖 Pillow)
├── bi_api_test/              # ✅ bi-admin 贴图包管理套件(32 用例,已就绪)
│   ├── client.py             #   BiAdminClient(继承 BaseClient)
│   ├── conftest.py           #   bi fixtures(client / draft_pack / 载荷工厂)
│   ├── check_conn.py         #   连通+登录自检
│   └── tests/                #   test_00_auth … test_06_tray_icon
└── dm_api_test/              # ✅ dm-api 套件(16 用例:聊天设置/我的最爱/贴图读)
    ├── client.py             #   DmApiClient:三层鉴权(AES旁路 Encversion + 签名 + token)
    ├── conftest.py           #   dm fixtures(dm_client / fav_cleaner)
    └── tests/                #   test_00_smoke(鉴权链路)… test_03_sticker_read
└── im_test/                 # ✅ dm-im 长连接套件(心情回应,WebSocket)
    ├── frame.py / proto_min.py  #   帧编解码 + 极简 protobuf(不引 protoc)
    ├── client.py             #   ImWsClient:连WS+CM_LOGIN+发回应+收ACK(自反应免好友)
    └── tests/                #   test_00_login … test_01_reaction
```

## 怎么加一个新服务套件(如 dm-im)

1. 新建 `dm_im_test/`(带 `__init__.py`)、`dm_im_test/tests/__init__.py`;
2. `dm_im_test/client.py`:`class DmImClient(BaseClient)`,补登录/鉴权头和接口方法;
3. `dm_im_test/conftest.py`:读该服务的 `.env` 变量,提供 `client` fixture;
4. 在 `pytest.ini` 的 `testpaths` 加 `dm_im_test`,`conftest.py` 的 `_SUITE_MARKERS` 加 `"dm_im_test": "dm_im"`;
5. 写 `dm_im_test/tests/test_*.py`。共享的 HTTP/信封/资产都在 `common/`,不重复造。

## 运行(PyCharm 或命令行)

```
pytest                      # 全部套件
pytest -m bi                # 只跑 bi 套件(靠目录自动标记)
pytest -m dm_api            # 只跑 dm-api 套件
pytest -m im                # 只跑 dm-im 心情回应(WebSocket,需 IM_* 配置)
pytest bi_api_test/         # 也可直接按目录跑
pytest -m "bi and not write"   # bi 的只读用例(不写库,最安全)
pytest -m "not s3"          # 跳过依赖 S3 的用例
```

先跑连通自检:`python bi_api_test/check_conn.py`(填完 .env 后)。

## 配置

复制 `.env.example` 为 `.env`,按前缀填对应服务:
- bi:`BI_BASE_URL`、`BI_USERNAME`(手机号)、`BI_PASSWORD`(MD5,取浏览器 payload 值);
- dm-api:`DM_API_BASE_URL`、`DM_API_APP_ID`/`DM_API_APP_SECRET`(查库 `sys_apps`)、`DM_API_WIPS`(Encversion 旁路值,跳过 AES)、`DM_API_TOKEN`(live 抓)。

未配置的服务对应套件会整体 **skip**,不报错。

**dm-api 三层鉴权说明**:用户接口在网关串了 AES 加密 + 签名 + token 三层。客户端的对付方式:
① 带 `Encversion=<WIPs值>` 头旁路 AES(body 走明文);② 每请求生成 nonce,把 `app_id+sign`
放 query、业务参数放 JSON body,`sign=UPPER(MD5(MD5(app_id)+MD5(appSecret+nonce)))`;③ 带 `token` 头。
先跑 `test_00_smoke`——它按返回 code 告诉你哪层没过(1020/1021=AES、1006/1007=签名、401=token)。

## markers

| marker | 含义 |
|---|---|
| `bi` / `dm_api` / `dm_im` | 服务套件(按目录**自动**打,不用手写装饰器) |
| `write` | 会写库/改状态(有副作用,用例自带清理) |
| `s3` | 依赖测试环境 S3 |
| `tray_icon` | 需配 `BI_TRAY_ICON_*` 才跑 |

## 环境安装(Windows 云主机,离线)

见随包的 `offline_wheels/安装说明.txt`。要点:
1. 装 Python 3.9~3.12(`python-3.12.8-amd64.exe`,勾 Add to PATH);
2. PyCharm 建 venv 解释器;
3. 离线装依赖:`pip install --no-index --find-links=<离线包目录> -r requirements.txt`。
