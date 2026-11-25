# 覆盖报告

生成日期：2026-11-26，Asia/Shanghai。
域名规则：352；公网 IP/ASN 规则：5。
源规则完整包含：773/773。
校验范围：域名规则匹配、源规则包含关系与公网 CIDR 集合。

## 24 个 Antigravity 关键域名

结果：**24/24**。

| 域名 | 用途 | 结果 | 命中规则 |
|---|---|---|---|
| antigravity.google | Antigravity 主域 | 通过 | `DOMAIN-KEYWORD,antigravity`; `DOMAIN-KEYWORD,google` |
| antigravity-unleash.goog | Antigravity 特性开关 | 通过 | `DOMAIN-SUFFIX,goog`; `DOMAIN-KEYWORD,antigravity` |
| antigravity-pa.googleapis.com | Antigravity 后端 | 通过 | `DOMAIN-KEYWORD,antigravity`; `DOMAIN-KEYWORD,google` |
| antigravity.googleapis.com | Antigravity 后端 | 通过 | `DOMAIN-KEYWORD,antigravity`; `DOMAIN-KEYWORD,google` |
| accounts.google.com | OAuth 登录必经 | 通过 | `DOMAIN-KEYWORD,google` |
| myaccount.google.com | 账号页 / ToS 国家 | 通过 | `DOMAIN-KEYWORD,google` |
| ogs.google.com | 登录页服务菜单 | 通过 | `DOMAIN-KEYWORD,google` |
| apis.google.com | Google 账号框架 | 通过 | `DOMAIN-KEYWORD,google` |
| clients6.google.com | 登录页伴随请求 | 通过 | `DOMAIN-KEYWORD,google` |
| content-autofill.googleapis.com | 登录表单填充 | 通过 | `DOMAIN-KEYWORD,google` |
| oauth2.googleapis.com | token 刷新 | 通过 | `DOMAIN-KEYWORD,google` |
| www.googleapis.com | 通用 API | 通过 | `DOMAIN-KEYWORD,google` |
| storage.googleapis.com | 安装包 / 素材 | 通过 | `DOMAIN-KEYWORD,google` |
| cloudcode-pa.googleapis.com | Antigravity 主 API | 通过 | `DOMAIN-KEYWORD,cloudcode`; `DOMAIN-KEYWORD,google` |
| daily-cloudcode-pa.googleapis.com | Antigravity 主 API daily | 通过 | `DOMAIN-KEYWORD,cloudcode`; `DOMAIN-KEYWORD,google` |
| daily-cloudcode-pa.sandbox.googleapis.com | Antigravity 沙箱 | 通过 | `DOMAIN-KEYWORD,cloudcode`; `DOMAIN-KEYWORD,google` |
| aida.googleapis.com | Gemini 后端 | 通过 | `DOMAIN-KEYWORD,google` |
| aiplatform.googleapis.com | Vertex AI | 通过 | `DOMAIN-KEYWORD,google` |
| generativelanguage.googleapis.com | Gemini API | 通过 | `DOMAIN-KEYWORD,generativelanguage`; `DOMAIN-KEYWORD,google` |
| lh3.googleusercontent.com | 头像 / 图片 | 通过 | `DOMAIN-KEYWORD,google` |
| ssl.gstatic.com | 静态资源 | 通过 | `DOMAIN-SUFFIX,gstatic.com` |
| www.google.com | Google 主站 | 通过 | `DOMAIN-KEYWORD,google` |
| play.google.com | Play | 通过 | `DOMAIN-KEYWORD,google` |
| mail.google.com | Gmail | 通过 | `DOMAIN-KEYWORD,google` |

## 扩展匹配检查

结果：**19/19**。

| 域名 | 用途 | 结果 | 命中规则 |
|---|---|---|---|
| ai.studio | AI Studio 独立域名 | 通过 | `DOMAIN-SUFFIX,ai.studio` |
| gemma.ai | Gemma | 通过 | `DOMAIN-SUFFIX,gemma.ai` |
| deepmind.com | DeepMind | 通过 | `DOMAIN-SUFFIX,deepmind.com` |
| gemini.google | Gemini 独立主域 | 通过 | `DOMAIN-KEYWORD,google` |
| notebooklm.google | NotebookLM 独立主域 | 通过 | `DOMAIN-KEYWORD,google` |
| jules.google | Jules | 通过 | `DOMAIN-KEYWORD,google` |
| flow.google | Flow | 通过 | `DOMAIN-KEYWORD,google` |
| opal.google | Opal | 通过 | `DOMAIN-KEYWORD,google` |
| googlevideo.com | Google 视频资源 | 通过 | `DOMAIN-KEYWORD,google` |
| gcr.io | Google Container Registry | 通过 | `DOMAIN-SUFFIX,gcr.io` |
| run.app | Cloud Run 公共后缀 | 通过 | `DOMAIN-SUFFIX,run.app` |
| appspot.com | App Engine 公共后缀 | 通过 | `DOMAIN-KEYWORD,appspot` |
| ai.google.dev | Google AI 开发入口 | 通过 | `DOMAIN-KEYWORD,google` |
| probe.goog | 验证 .goog 后缀覆盖 | 通过 | `DOMAIN-SUFFIX,goog` |
| colab.example.net | 验证 colab 源关键词范围 | 通过 | `DOMAIN-KEYWORD,colab` |
| developerprofiles.example.net | 验证 developerprofiles 源关键词范围 | 通过 | `DOMAIN-KEYWORD,developerprofiles` |
| generativelanguage.example.net | 验证 generativelanguage 源关键词范围 | 通过 | `DOMAIN-KEYWORD,generativelanguage` |
| cloudcode.example.net | 验证 cloudcode 源关键词范围 | 通过 | `DOMAIN-KEYWORD,cloudcode` |
| antigravity.example.net | 验证 antigravity 源关键词范围 | 通过 | `DOMAIN-KEYWORD,antigravity` |

## 公网 IP

- `74.125.0.0/16`
- `172.110.32.0/21`
- `173.194.0.0/16`
- `216.73.80.0/20`
- `2620:120:e000::/40`
- IPv4 CIDR 地址数量：137216。
- ASN：当前无 Google 专属 ASN 规则。

基准域名来源：[dayvight 校验脚本](https://github.com/dayvight/loon-antigravity-rules/blob/15cfe975509ec30d079a2e74a0b104edce653b06/scripts/check-coverage.mjs#L41-L66)。
