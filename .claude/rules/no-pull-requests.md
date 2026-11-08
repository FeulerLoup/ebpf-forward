# 提交方式：直接提交到 master，不使用 PR

本项目所有改动都直接提交到 `master` 并推送到 `origin/master`，**不使用 Pull Request**。

- 不创建 PR，不把功能分支推送到远端（包括 `claude/*` 这类会话 / worktree 分支），也不要提议“开 PR”。
- 在 worktree 或会话分支上完成的工作：验证通过后 rebase 到最新的 `master`（保持线性历史），直接推送 `master`，
  然后删除该分支和 worktree。
- 没有 PR 评审这一关，推送前要在本地完成验证（至少 `cargo fmt --all --check` 和能跑的编译 / 测试）。
  推送 `master` 会触发 CI（`.github/workflows/release.yml`），以 CI 结果为最终依据。
