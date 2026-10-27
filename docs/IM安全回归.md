# Vuln20 / Vuln22 dev 自测

本套件只覆盖已交付的 Vuln20（登录 token 与 UID 绑定）和 Vuln22（私密频道成员校验）。Vuln21 的 LiveKit 改动已按本版本要求回退，不运行相关安全验收。

本次交付先完成脚本与本地协议验证，**尚未连接真实 dev**。需要配置后自行运行，下列命令只收集本次相关用例。

## 准备

在仓库根目录使用 Python 3.9 或以上版本，安装 `requirements.txt`，将 `.env.example` 复制为 `.env` 并填写安全回归配置。已有 `.env` 时补充对应字段即可，不要覆盖原配置。

| 配置 | 要求 |
| --- | --- |
| `IM_SECURITY_ENV` | 必须显式为 `dev`；留空跳过，其他值失败 |
| `IM_SECURITY_DEPLOYMENT` | 本次 dev 实际部署的提交号或镜像版本，用于报告追溯 |
| `IM_SECURITY_WS_URL` | 显式填写 dev im-gateway 的完整 `ws://` 或 `wss://` 登录地址 |
| `IM_SECURITY_TCP_URL` | 可选的 `tcp://host:port` 或 `tls://host:port`，未填时仅 TCP 用例跳过 |
| `IM_SECURITY_HTTP_BASE_URL` | 显式填写 dev http-gateway 根地址，不带 `/channel/v1` |
| `IM_SECURITY_USER_ID` / `IM_SECURITY_TOKEN` | 专用账号 A，本人的有效 IM token；可复用 `IM_USER_ID` / `IM_TOKEN` |
| `IM_SECURITY_USER_ID2` / `IM_SECURITY_TOKEN2` | 专用账号 B，本人的有效 IM token；可复用 `IM_USER_ID2` / `IM_TOKEN2` |
| `IM_SECURITY_CHANNEL_ID` | 私密频道 P：A 是成员，B 从未加入或已退出；可复用 `IM_CHANNEL_ID` |
| `IM_SECURITY_CHANNEL_MESSAGE_ID` | P 中固定的全员普通广播消息 ID，用于按 ID 正控和锚定历史读取 |
| `IM_SECURITY_BROADCAST_CONFIRMED` | 已用可信证据确认固定消息原本对 B 可见时设为 `1`；否则主频道回归跳过 |
| `IM_SECURITY_OTHER_CHANNEL_ID` | 可选频道 Q：B 是成员、A 不是成员，用于混合频道请求 |
| `IM_SECURITY_ALLOW_LOGIN` | 默认为 `0`；准备好专用账号后设为 `1` 才运行 Vuln20 |

A/B 必须为不同账号，分别使用各自的 token。P、Q 预先准备至少一条对应成员可见、正文非空的普通广播消息，不要用心情回应或仅特定用户可见的消息。固定消息的全员广播属性不会包含在拉取响应中，脚本无法从 A 能读取这一点证明 B 原本可见：应先让 B 入群确认可读同一消息再退出，或由可信发送记录确认它未设置定向用户。确认后再置 `IM_SECURITY_BROADCAST_CONFIRMED=1`，报告会标记这一人工前置条件；未确认不能据此关闭 Vuln22。

P 的单页上限测试需至少 101 条可读普通消息，否则该项明确跳过；脚本不会发送消息补数。HTTP 按同一个 `client_type` 选取消息正文，默认 Web（2），可通过 `IM_SECURITY_CLIENT_TYPE` 修改为 App（0）或 PC（1）。安全套件不自动复用旧的 `IM_WS_URL` / `IM_HTTP_BASE_URL`，以免旧配置指向其他环境；`ENV=dev` 只是环境声明，仍需人工核对地址。

部署需包含本次修复的 login-srv、im-gateway、channel-pull-server。HTTP 用例通过现有 http-gateway 调用 channel-pull-server。多实例时应先确认所有目标实例的版本一致；经负载均衡的一次执行仅证明实际命中的请求路径，不能证明每个实例都已更新。

配置文件 `.env` 和本地报告目录 `.reports/` 均忽略提交。报告只写环境、部署版本、业务码与计数，不保存 token 或消息正文。不要开启 `--showlocals`、HTTP 调试日志或额外响应转储。

## 本地协议验证

以下三个文件只使用本地模拟，不连接任何服务，可在填配置前后重复运行：

```bash
python -m pytest im_test/tests/security/test_config_unit.py \
  im_test/tests/security/test_login_protocol_unit.py \
  im_test/tests/security/test_channel_protocol_unit.py -v
```

检查严格帧长度、ACK 序号、protobuf 字段、HTTP 状态和配置脱敏。它们通过仅证明测试脚本的本地校验正常，不能替代真实 dev 回归。

## Vuln22：频道读取

```bash
python -m pytest im_test/tests/security/test_channel_access.py -v \
  -o junit_family=xunit1 --junitxml=.reports/im-security-v22.xml
```

共 18 项，分别覆盖 `/channel/v1` 与 `/channel/v2`：

- A 先成功读取 P 的非空会话、固定广播消息的按 ID 回源与锚定历史；B 用自己的有效 token 完成空频道鉴权正控。固定广播消息的原始可见性由配置者事先确认，写入报告前置条件。
- B 用本人 UID 或在请求体伪造 A 的 UID，请求 P 的 `sessions`、`offlineMessages`、`msg/by_id`。前两者必须成功但为空；按 ID 回源必须明确 HTTP 403、protobuf `errcode=403` 且不附带消息或状态。
- 配置 Q 后，同一个请求同时包含 P、Q，只能返回 B 有权限的 Q 数据。
- 对 P 先通过有界分页证明第 101 条不同消息存在，再请求 `count=1000`，确认单频道最多返回 100 条。

HTTP 用例不发消息、不回传已读或投递 ACK、不修改频道成员关系。传输失败、401、5xx、重定向、HTML、截断 protobuf，以及正控为空均会失败，不能作为访问控制通过。缺少 Q 或不足 101 条时，对应项是跳过，其他已配置项继续运行。

## Vuln20：登录身份绑定

确认 A/B 的 App、PC、H5 已退出，或接受测试会影响其在线状态，再设置 `.env` 中的 `IM_SECURITY_ALLOW_LOGIN=1`。

```bash
python -m pytest im_test/tests/security/test_login_uid.py -v \
  -o junit_family=xunit1 --junitxml=.reports/im-security-v20.xml
```

WS、TCP 各一项。每项依次确认 A 本人登录、B 本人登录成功且 ACK UID 正确，再使用 A token 声明 B UID，必须收到明确的 `ERR_LOGIN_AUTH (0x8101)`，最后再次确认 A 本人登录成功。断连、超时或其他错误码均失败。未配置的传输入口明确跳过。

每次探测结束关闭连接；登录会更新在线状态并可能踢掉原会话，关闭连接不会恢复原会话。测试结束后按需要重新登录 A/B，无需清理消息或成员数据。

## 可选：退群立即失权与重新加入

这部分检查成员状态的新鲜度，需要人工改变 B 的成员关系。脚本只读，不调用退群、踢人、重入、建群或关闭接口。

另准备专用频道 C，与 P 不同，初始 A/B 都是成员。配置：

```dotenv
IM_SECURITY_LIFECYCLE_CHANNEL_ID=
IM_SECURITY_LIFECYCLE_MESSAGE_ID=
IM_SECURITY_MEMBERSHIP_PHASE=member_warm
```

固定消息必须是 C 中双方可见的同一条非空普通广播，并且在三个阶段始终为最新普通消息。`sessions` 只返回末条；测试期间保持频道安静。不要改用不存在、已撤回或重入后新发的消息来完成负向检查；若前置条件改变，修正后重新跑整条链。

1. B 仍在 C 时，设置 `member_warm`，运行下面的命令，预热并确认 B 在三个入口都可读。
2. 手工用 B **主动退出** C（不要用踢人，以免黑名单影响重入），立即设置 `after_quit`，运行相同命令。每个入口只请求一次；任何一次泄漏直接失败，不轮询等缓存过期。
3. 让 B 重新加入 C，保持同一固定消息与部署版本，设置 `rejoined`，再次运行，确认三个入口恢复可读。结束后可按测试前约定恢复 C 的成员关系。

```bash
# 每个阶段使用不同报告名保存；例如 after_quit / rejoined 替换下方 member_warm
python -m pytest im_test/tests/security/test_channel_membership_phases.py -v \
  -o junit_family=xunit1 --junitxml=.reports/im-security-member_warm.xml
```

每次选中阶段只有 v1/v2 两项执行，其余四项明确跳过。未选择阶段或缺 C/消息配置会跳过。退群阶段仍要求 A 能读取固定消息、B token 鉴权有效；避免数据不存在或 token 过期造成假通过。

单个阶段通过不表示完整退群/重入链通过，报告中 `membership_chain_complete` 固定为 `False`。必须保留同一环境、版本、C 和固定消息的三个阶段报告，并记录退出后到执行检查的间隔，才能人工确认整链结果。脚本本身不测量人工退群到请求之间的延迟。

## 记录结果

每次记录实际环境、部署版本、执行命令、通过/失败/跳过数量，以及手工阶段和数据恢复情况。pytest 即便全部跳过也可能返回退出码 0，必须检查 summary 与 skip 原因；跳过、未部署、缺凭证均属于未验证。WS/TCP 若只跑了一个入口，报告中也应写明另一个未验证。
