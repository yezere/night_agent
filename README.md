# night_agent

`night_agent` 是一个 AI 主导的多 Agent Java 代码审计系统。它通过 SourceAgent、SinkAgent、JoernQueryAgent、TracerAgent、JudgeAgent、PocAgent、ReportAgent 和 Observer 协作完成审计，并输出中文 Markdown 报告。

当前环境路径：

```bash
cd ~/Desktop/night_agent/night_agent_env/night_agent
```

快速启动：

```bash
bun install
export GLM_API_KEY="..."
bun run --cwd apps/web build
bun run apps/cli/src/main.ts serve --port 3000
```

新机器安装依赖并构建：

```bash
scripts/install-deps.sh
scripts/start-server.sh
```

`install-deps.sh` 会安装/检查 Bun、Java 17、ripgrep、Joern，并默认把 Joern 放到 `$HOME/joern/joern-cli`。历史记录 SQLite 默认持久化在当前项目的 `.night-agent/runs/night_agent.sqlite`。

CLI demo：

```bash
bun run apps/cli/src/main.ts audit test/fixtures/vulnerable-app \
  --provider glm \
  --model glm-5.1 \
  --base-url https://open.bigmodel.cn/api/coding/paas/v4 \
  --out /tmp/night_agent_demo_vuln
```

批量串行审计：

```bash
cat > /tmp/night_agent_targets.txt <<'EOF'
/path/to/project-a
/path/to/project-b
https://github.com/example/project-c.git
EOF

bun run batch \
  --targets /tmp/night_agent_targets.txt \
  --reports-dir /tmp/night_agent_reports \
  --provider glm \
  --model GLM-5.1 \
  --base-url https://open.bigmodel.cn/api/coding/paas/v4
```

`batch` 会按目标列表串行执行；中途断掉后重新执行同一条命令会读取 `/tmp/night_agent_reports/batch-state.json`，跳过已完成目标并继续未完成目标。每个项目的原始产物在 `/tmp/night_agent_reports/.runs/`，最终 Markdown 报告和 `batch-summary.md` 会集中放进 `--reports-dir`。

当前版本要点：

- SourceAgent/SinkAgent 会先强制 `file_tree`，再由模型主动 `rg/read_file`。
- 大项目要求 AI 至少读取多个不同文件后才接受 final JSON。
- pre-scan 之后会触发第二轮 AI refine，让模型根据预扫线索继续 tree/read_file 查漏补缺。
- 默认最多追踪 `200` 个 hypothesis。
- StaticVerifierAgent 会输出 Trace/Barrier/Missing；Observer 会监管 Verifier 证据质量，必要时触发一次重判，未解决则降级为 `maybe_revisit`。
- 运行时仍使用内存 Store 共享状态；阶段边界和 Tracer/Verifier 批次会写 checkpoint，被系统强制关闭后可在历史记录里点击“继续”复用 source/CPG 和已落盘状态。
- CLI 支持 `batch` 批量串行审计，可自动续跑并把多项目漏洞报告集中存入指定目录。
- 前端支持审计动态聚合、折叠展开、Markdown 全屏预览和下载。
- 前端回归对比面板可按类名/路由/hyp id 查看 Verifier Trace、Barrier、Missing 和 `verifier-integrity` 检查点。
- 工具调用 trace 写入 `<outputDir>/llm-debug/llm-tool-trace.jsonl`。

## 免责声明

本项目及相关文章内容仅供网络安全教育、学习交流与合法授权的安全研究使用，不得用于任何非法、未授权、攻击性或有害目的。

使用者在学习和使用本项目涉及的技术、工具、思路或代码时，应确保已获得目标系统所有者的明确授权，并严格遵守所在地相关法律法规。任何因误用、滥用或未经授权使用本项目内容而造成的直接或间接损失、法律责任或其他后果，均由使用者自行承担，项目作者不承担任何责任。

作者博客：https://n1ght.cn/

## 开源协议

本项目采用 GNU General Public License v3.0 only（GPL-3.0-only）开源协议发布。

- 协议标识：`GPL-3.0-only`
- 完整协议文本：见 [LICENSE](LICENSE)
- 版权声明：Copyright (C) 2026 n1ght <night05@qq.com>
- 使用、复制、修改和再分发本项目代码时，应保留原始版权声明和协议文本。
- 分发本项目或基于本项目修改后的版本时，应按 GPL-3.0-only 的要求提供相应源代码，并继续使用 GPL-3.0-only 授权。
- 本项目按“原样”提供，不包含任何明示或默示担保；详见 GPL-3.0-only 中关于无担保和责任限制的条款。
- 本项目引用的第三方依赖、工具或示例项目仍遵循其各自的许可证和使用条款。

上述免责声明仅用于限定项目使用场景和责任边界，不削减 GPL-3.0-only 授予使用者的权利。
