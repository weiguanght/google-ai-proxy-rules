# Google / Gemini / Antigravity Proxy Rules

本项目合并指定来源的 Google、Gemini、Antigravity 域名与公网 IP 规则。

- 生成日期：**2026-11-26，Asia/Shanghai**。
- 合并后：**352 条域名规则、4 条 IPv4 CIDR、1 条 IPv6 CIDR、0 条 ASN 规则**。
- 24 个关键域名 **24/24**；扩展检查 **19/19**。
- 纳入的 773 条不同源规则，其完整静态匹配范围均被最终规则覆盖。

## 使用哪个文件

| 用途 | Loon | Clash / Mihomo |
|---|---|---|
| 域名 + 公网 IP 汇总 | [Google-AI.list](rules/loon/Google-AI.list) | [Google-AI.yaml](rules/clash/Google-AI.yaml) |
| 仅域名 | [Google-AI-Domains.list](rules/loon/Google-AI-Domains.list) | [Google-AI-Domains.yaml](rules/clash/Google-AI-Domains.yaml) |
| 仅公网 IP | [Google-AI-IP.list](rules/loon/Google-AI-IP.list) | [Google-AI-IP.yaml](rules/clash/Google-AI-IP.yaml) |

汇总文件和分表二选一，不重复引入。策略组由客户端配置指定，规则文件不写死代理节点。

## 订阅地址

仓库：[weiguanght/google-ai-proxy-rules](https://github.com/weiguanght/google-ai-proxy-rules)。

| 内容 | Loon | Clash / Mihomo |
|---|---|---|
| 汇总 | [订阅](https://raw.githubusercontent.com/weiguanght/google-ai-proxy-rules/main/rules/loon/Google-AI.list) | [订阅](https://raw.githubusercontent.com/weiguanght/google-ai-proxy-rules/main/rules/clash/Google-AI.yaml) |
| 仅域名 | [订阅](https://raw.githubusercontent.com/weiguanght/google-ai-proxy-rules/main/rules/loon/Google-AI-Domains.list) | [订阅](https://raw.githubusercontent.com/weiguanght/google-ai-proxy-rules/main/rules/clash/Google-AI-Domains.yaml) |
| 仅公网 IP | [订阅](https://raw.githubusercontent.com/weiguanght/google-ai-proxy-rules/main/rules/loon/Google-AI-IP.list) | [订阅](https://raw.githubusercontent.com/weiguanght/google-ai-proxy-rules/main/rules/clash/Google-AI-IP.yaml) |

## 合并口径

- blackmatrix7 Google、Gemini：纳入域名和公网 IP。
- dayvight：纳入 google-auth、google-full；保留整个 .goog 后缀的覆盖。
- antigravity-proxy：只读取安装器的规则数组和 PAC 的 Google 核心域名分支。
- VPSDance：纳入 google-ai，并提取 global/all 中属于 Google 范围的规则。
- 重复规则合并；被更广的后缀或关键词完全包含的规则移除。
- 公网 CIDR 按地址集合等价合并；ASN 按编号保留。

本项目不执行安装器，不修改 Antigravity 应用，不注入代理环境变量。
PROCESS-NAME、USER-AGENT、PAC 默认代理分支和私网 DIRECT 排除项不纳入生成规则。
VPSDance 中 OpenAI、Anthropic 等其他平台的网段和 ASN 不混入 Google IP 分表。

## 广覆盖的实际范围

以下关键词按域名字符串匹配，不限定为 Google 官方域名：
`antigravity`, `appspot`, `blogspot`, `cloudcode`, `colab`, `developerprofiles`, `generativelanguage`, `gmail`, `google`, `recaptcha`。
Cloud Run / App Engine 等公共后缀也包含第三方租户。
Google 账号、Gmail 等通用服务同样会匹配到所选策略组。

当前公网 CIDR 取自 blackmatrix7 的 Google.list。
IP / ASN 规则带 no-resolve，按已有目标 IP 匹配。
关键链路检查用于回归；源规则包含检查用于验证合并后的覆盖范围。

## 导入客户端

使用 [Loon 示例](examples/loon.conf) 或 [Clash/Mihomo 示例](examples/clash.yaml) 中的真实订阅地址。
将 Google-AI 换成客户端已有的策略组名。

Clash/Mihomo rule-provider 使用 behavior: classical 和 format: yaml。
需要分别指定域名与 IP 策略时，引入两个分表；需要同一策略时，引入汇总文件。
需要让这些域名使用专用策略时，规则应排在会抢先命中的通用规则和 FINAL/MATCH 之前。

## 更新与核验

条件：终端当前目录为本项目根目录。Python 3.10+，不需要第三方 Python 包。
目的：从配置中的四个仓库取得当前指定分支，固定提交后重新生成规则。

```bash
python3 tools/update_rules.py
```

目的：只用附带快照离线重建。

```bash
python3 tools/update_rules.py --offline
```

目的：核验快照哈希、覆盖结果与所有生成文件，不改动文件。

```bash
python3 tools/update_rules.py --check
python3 -m unittest discover -s tests -v
```

提取结构变化、下载失败或覆盖检查失败时，更新命令退出，保留旧生成文件。
工具只访问 config/sources.json 中指定的仓库、规则路径和随附许可证路径。

## 追溯

- [来源与固定提交](SOURCES.md)
- [覆盖报告](reports/coverage.md)
- [覆盖数据](reports/coverage.json)
- [最终规则的源规则映射](reports/provenance.json)
- [被排除的规则及原因](reports/exclusions.json)
- [来源清单和文件哈希](sources/manifest.json)
- [上游许可与署名](NOTICE.md)
