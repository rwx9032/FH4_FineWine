# HANDOFF — FH4 FineWine

现场时间：2026-10-28（Asia/Shanghai）。本文件是接手时的准确现场；先读它，再看 README/兼容性文档。

## 0. 一句话状态

代码、离线测试、隔离环境中的安装/回滚链路已完成并验证；**没有目标 FH4 可执行文件，因此游戏启动、进入世界和实际帧率仍未验证**。未对 `/Applications/CrossOver.app`、任何正在使用的 bottle 或 Endfield 会话做修改。仓库提交/推送状态见第 8 节。

## 1. 用户约束（仍然有效）

- 可正常提交并推送 `main`；**禁止 force push**。Git：`/Library/Developer/CommandLineTools/usr/bin/git`；Python：`/opt/homebrew/bin/python3.13`。
- 不接受 Xcode 许可证、不使用 sudo；不输出 Git 凭据。
- 不改游戏画质、video 注册表；不干扰正在运行的 Endfield。
- 不覆盖运行中的 CrossOver、不重启 Endfield。
- 禁止伪造 Apple 闭源组件或用 vkd3d 冒充 D3DMetal。
- 无需重复执行 pkg 安装器。
- “安装转换器”不等于“CrossOver 已升级 D3DMetal 4”。
- 不为延长时间空等或重复已通过的测试。
- 用户接手时以本文件为准。

## 2. 仓库与运行方式

仓库：`https://github.com/rwx9032/FH4_FineWine.git`（本地 `main`）。所有工具在 `tools/fh4.py`，入口 `install.sh`。

```sh
./install.sh check  --app <CrossOver.app> --bottle <bottle> [--gptk-external <external>]
./install.sh install --app <CrossOver.app> --bottle <bottle> --backup <不存在路径> \
    (--fh4-exe <exe> --fh4-sha256 <sha> | --allow-unverified-game) [--replace]
./install.sh rollback <backup>
./install.sh patch-kernelbase <stock> <new>
./install.sh inspect <dll>...
```

`check` 是只读的（不查进程、不写注册表）；`install`/`rollback` 要求全局无 Wine/CrossOver 进程。这是保守策略：Endfield 运行时，即使目标是另一份 app/bottle 也会被拒绝。隔离验证时用测试 harness mock 掉了 `active()`，生产代码没有放宽。

## 3. Stage A：组件与来源

- Metal Shader Converter 4.0b3 pkg（SHA-256 `449833…be622`）只含 CLI `/usr/local/bin/metal-shaderconverter`、头文件和 `libmetalirconverter.dylib`；**不是** D3DMetal 运行时。
- Evaluation DMG（`9550b8…40a7b0`）的 `redist/lib/external` 才是 D3DMetal 4.0b3：`libd3dshared.dylib` `e985a9e0…41f1`（250672 B）、`D3DMetal.framework` 二进制 `b16aab78…31e1`（7973168 B），均 x86_64。
- 顶层 GPTK DMG：`32ce2065…3b87b`。完整表见 `docs/PROVENANCE.md`。
- 结论：转换器与运行时是不同组件；不执行 pkg，不复制伪造组件。

## 4. Stage B：代码加固（已落地）

`tools/fh4.py` 现有关键行为：

- 备份路径必须是绝对/相对均可，但父目录解析后存在、目标不存在、位于 app/bottle 之外；拒绝 symlink 穿越。
- app、bottle、注册表、目标 DLL 均做 symlink/越界检查；写入使用同目录临时文件 + `os.replace`，不跟随最终 symlink。
- manifest format 2：app 树摘要、Info.plist 哈希、bottle 条目哈希/模式/symlink 目标、payload 哈希、GPTK 信息、FH4 证据、`bottle_override` 原值。
- 回滚先校验 manifest/树/条目，再 staging；任一步失败会反向恢复 app 与 bottle，保留 stage 供人工处理。
- `check` 与 `install` 的空闲要求已分离；`ps` 失败/空输出都按“非空闲”处理。
- 固定 RVA VEH 不再无条件启用：`install` 需要 `--fh4-exe` + `--fh4-sha256`，或显式 `--allow-unverified-game`。
- 重复安装需 `--replace`；foreign 状态一律拒绝覆盖。
- 新增 `inspect`：PE 架构/导入/导出序号/COFF 模块与函数名（只读）。
- **本阶段新增的两个关键修复**（来自 Stage C 实测）：
  1. 环境变量补齐原工具的 `D3DM_VENDOR_ID=0x8086`、`D3DM_DEVICE_ID=0x56a1`。
  2. 持久写入 `HKCU\Software\Wine\DllOverrides` 的 `"apd12"="builtin"`，并把原行以 base64 存入 manifest；回滚精确恢复。原因见第 5 节。

测试：`python3.13 -m unittest discover -s tests` → **22 tests, OK (skipped=1)**。跳过的是需要 `FH4_STOCK_KERNEL` 的真实 stock 测试；本地有 payloads 时 `test_real_payload_inventory_when_present` 会执行。

## 5. Stage C：隔离运行验证（关键证据）

环境：CrossOver 26.3.0.39832 的**应用副本**与私有 win64 bottle，位于 `/tmp/fh4-CrossOver-test.app`、`/tmp/fh4-iso-bottle`；GPTK 4.0b3 external 来自只读挂载 `/tmp/fh4-gptk-eval/redist/lib/external`。未触碰 `/Applications/CrossOver.app`。

实际装载链：

```
game/probe
 → WINEDLLPATH 中的 d3d12.dll（Apple GPTK / Highball shim，11 exports ordinal 100–110）
 → HB_D3D12_REAL=apd12.dll
 → apd12.dll（builtin；必须在 user.reg 覆盖，见下）
 → x86_64-unix/apd12.so → ../../external/libd3dshared.dylib
 → D3DMetal.framework 4.0b3
```

发现与解决：

- 仅把 `apd12.dll` 放进 `lib64/apple_gptk/wine/x86_64-windows` 和 `system32` 时，loader 按 `apd12=native` 查找并报 `c0000135`，即使文件存在且哈希正确。
- 把**相同字节**改名为 `foo.dll` 后 native 装载成功 → 不是 PE 损坏，而是 `apd12` 这个名字的默认 native 解析。
- `--env WINEDLLOVERRIDES=apd12=b` 或 `--dll apd12=b` 可装载；但 CrossOver 的 Perl 启动器在读取 bottle 环境后会 `delete $ENV{WINEDLLOVERRIDES}`，所以写 `cxbottle.conf` 无效。
- 最终修复：直接维护 bottle `user.reg` 的 `[Software\\Wine\\DllOverrides]`，最小改动 `"apd12"="builtin"`；工具记录原行并可在回滚时恢复。
- `D3D12CreateDevice` 64 位探针：`rcx=NULL, edx=0xb000, r8=&IID_D3D12Device, r9=&out`；返回 `S_OK` 且 out 非空。第一次探针崩溃是探针自身把 out 放在只读 `.rdata`（访问冲突写 `0x140002120`），不是 apd12 失败；改为栈上 out 后通过。

实际命令（在应用副本上；生产环境请替换路径）：

```sh
WINEDEBUG=+module <copy>/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine \
  --bottle /tmp/fh4-iso-bottle --scope private \
  --cx-app 'C:\fh4probe.exe'

<copy>/.../bin/wine --bottle /tmp/fh4-iso-bottle --scope private \
  --cx-app 'C:\fh4probe_call.exe'   # exit 0 = S_OK + 非空设备
```

安装/回滚实测：

1. 首次隔离安装成功（备份 `/tmp/fh4-install-backup`，安装前代码版本）。
2. 加入 D3DM/注册表修复后再次 `--replace` 安装成功（备份 `/tmp/fh4-install-backup-2`；manifest 中 `bottle_override.previous = "apd12"="builtin"`）。
3. 两次无 CLI override 的探针均 exit 0。
4. 回滚 backup-2 → `state=installed`（恢复为之前的 installed 状态）。
5. 回滚 backup（旧版，无 `bottle_override`）→ 手动恢复安装前 `user.reg` → `state=pristine`，`apd12` 原值 `native`。
6. 诊断文件（探针 EXE、`foo.dll`、`drive_c/apd12.dll`、`system32/apd12.so`）已从测试 bottle 清除。

注意：旧备份没有 `bottle_override` 字段，回滚时不会改注册表；这是为兼容旧 manifest 的有意行为。新备份始终包含该字段。

## 6. Stage D：可复现性

- 固定 FineWine 1.3.1 归档：commit `1b9d8e6c…bd06`，SHA-256 `3509cada…78d8c`，MIT。
- 三份载荷哈希、导出序号、COFF 模块/函数名已记录；`inspect` 可随时重放。
- `d3d12.dll` 的 COFF 模块包含 `d3d12.c` 和 MinGW CRT；函数名含 `DllMain` 等。`apd12.dll` 含 `ne_init_unix_call`、`ne_unix_call_dispatcher` 等。
- **没有源码**：COFF 只有名称/重定位，不能还原 shim 源码。仓库不提供占位 passthrough 冒充原 shim。
- kernelbase 补丁是确定性的：stock `ca72…39191b` → output `313a…0f182`，135 字节差异，固定 cave `0x8bf20`。

## 7. Stage E/F：测试、CI、发布边界

- 单元测试覆盖：配置幂等与 `WINEMSYNC` 保留；DllOverride 合并/幂等/恢复；manifest/snapshot 篡改；symlink 逃逸；签名失败回滚；回滚中途失败反向恢复；重复安装；foreign 拒绝；进程查询失败；游戏证据门。
- 离线 CI：`.github/workflows/tests.yml`，Ubuntu/macOS × Python 3.12/3.13，`unittest discover`；无网络、无 Apple 组件；需要载荷的测试自动跳过。
- 兼容性矩阵：`docs/compatibility.md`；来源与哈希：`docs/PROVENANCE.md`；隔离验证输出：`docs/verification.md`；从载荷复现：`docs/reproduce.md`。
- `.gitignore` 忽略 `payloads/`、`*.dll`、`*.dylib`、`*.so`、`*.dmg`、`*.app/`、`__pycache__`、回滚 stage。不得提交任何 DLL/DMG/Apple 组件/凭据/私人绝对路径。

## 8. 提交与发布状态

- 本次开始前仓库无任何已跟踪文件（全部 untracked）。
- 已完成：初始 commit `a977e34f325fcf2602d5baffa0dd14d4b272707b`，后续 `141b1e6`（交接记录）、`d06ab21`（注册表回滚测试）、`88c85db`（隔离验证与复现文档）、`2554dd9`（本记录更新）均已推送到 `origin/main`；未 force push，远端 `refs/heads/main` 与本地一致。
- GitHub Actions `tests`：run 1–5 全部成功（含 Ubuntu/macOS、Python 3.12/3.13）；run 5 对应 `2554dd9`。
- 初始提交 11 个文件、1500 行；`payloads/`、`__pycache__/` 未提交。
- 未打 tag、未创建 GitHub Release；在没有 FH4 运行验证前不应宣称“可玩”。

## 9. 未解决 / 下一步（按优先级）

1. **真实 FH4 验证（唯一实质阻塞）**：需要目标 `ForzaHorizon4.exe` 及其 SHA-256。用 `install --fh4-exe ... --fh4-sha256 ...` 安装到**可回滚的副本**，记录：能否启动、是否进入世界、`HB_TSSHIM_*` 日志、崩溃栈、帧率。不得在 Endfield 运行时操作。
2. 若 FH4 构建与固定 RVA 不匹配，VEH 补丁需要按新版本重新定位；当前工具会因 SHA 不符拒绝，这是正确行为。
3. 若要装进用户日常 CrossOver，先复制 app 与 bottle，验证回滚，再在空闲时执行；不要直接覆盖正在使用的 app。
4. 供应商签名无法恢复；如需分发，明确说明 ad-hoc 签名。
5. 可选的后续：把 `inspect` 输出保存为发布附件；为真实 FH4 构建增加固定哈希矩阵；在 CI 上跑一次确认 workflow。

## 10. 现场附件（本机临时目录，不属于仓库）

- `/tmp/fh4-CrossOver-test.app`、`/tmp/fh4-iso-bottle`：已恢复 pristine 的隔离副本。
- `/tmp/fh4-install-backup`、`/tmp/fh4-install-backup-2`：两次安装的备份/manifest（含 app 快照，体积较大）。
- `/tmp/fh4-gptk-eval/redist/lib/external`：只读挂载的 4.0b3 运行时。
- `/tmp/probe.exe`、`/tmp/probe_call.exe`、`/tmp/mkpe.py`：ABI/装载探针源码与二进制，仅诊断用。
- `/tmp/fh4-load.log` 等日志可能已滚动；以本文件记录的结果为准。

这些临时文件可删除；删除后仍可用仓库工具和用户提供的载荷重放验证。
