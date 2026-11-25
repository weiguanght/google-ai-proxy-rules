# 来源记录

每次更新先固定四个仓库的提交，再读取下面的明确文件。
完整 SHA-256、字节数和快照路径见 sources/manifest.json。

| 来源 | 文件 | 提交 | SHA-256 前 12 位 | 纳入规则出现次数 |
|---|---|---|---|---|
| bm7-google | [rule/Loon/Google/Google.list](https://github.com/blackmatrix7/ios_rule_script/blob/0b6897dc17e0c513d25449c935a9694818e32f0c/rule/Loon/Google/Google.list) | `0b6897dc17e0` | `8ad1014c13d4` | 695 |
| bm7-gemini | [rule/Loon/Gemini/Gemini.list](https://github.com/blackmatrix7/ios_rule_script/blob/0b6897dc17e0c513d25449c935a9694818e32f0c/rule/Loon/Gemini/Gemini.list) | `0b6897dc17e0` | `db8f69154426` | 13 |
| dayvight-auth | [rules/google-auth.list](https://github.com/dayvight/loon-antigravity-rules/blob/15cfe975509ec30d079a2e74a0b104edce653b06/rules/google-auth.list) | `15cfe975509e` | `8b714e1cf7cb` | 16 |
| dayvight-full | [rules/google-full.list](https://github.com/dayvight/loon-antigravity-rules/blob/15cfe975509ec30d079a2e74a0b104edce653b06/rules/google-full.list) | `15cfe975509e` | `ae7413629142` | 7 |
| xukun-install-js | [install.js](https://github.com/xukuncai-hub/antigravity-proxy/blob/f482397d69b133a942d3ebfd255b1dd8ffd4e8ba/install.js) | `f482397d69b1` | `11442fcd2970` | 10 |
| xukun-install-py | [install.py](https://github.com/xukuncai-hub/antigravity-proxy/blob/f482397d69b133a942d3ebfd255b1dd8ffd4e8ba/install.py) | `f482397d69b1` | `16e15dcf7b6e` | 10 |
| xukun-pac | [src/proxy_patch.js](https://github.com/xukuncai-hub/antigravity-proxy/blob/f482397d69b133a942d3ebfd255b1dd8ffd4e8ba/src/proxy_patch.js) | `f482397d69b1` | `d5682a0a5f71` | 11 |
| vps-google-ai | [rules/loon/google-ai.list](https://github.com/VPSDance/ai-proxy-rules/blob/1fe3a3db476eaae38837a3690daf57838faf6ca0/rules/loon/google-ai.list) | `1fe3a3db476e` | `411c0ef81441` | 51 |
| vps-global | [rules/loon/global.list](https://github.com/VPSDance/ai-proxy-rules/blob/1fe3a3db476eaae38837a3690daf57838faf6ca0/rules/loon/global.list) | `1fe3a3db476e` | `aeb1dc131a4b` | 52 |
| vps-all | [rules/loon/all.list](https://github.com/VPSDance/ai-proxy-rules/blob/1fe3a3db476eaae38837a3690daf57838faf6ca0/rules/loon/all.list) | `1fe3a3db476e` | `b1684f186649` | 52 |

PAC 只提取 Google 核心域名分支；不把默认代理分支转换为全流量规则。
