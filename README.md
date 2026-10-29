# FH4 FineWine

为 macOS CrossOver 26.3 + Apple GPTK 4.x 提供离线 FH4 兼容性移植工具。工具复用用户提供的 `d3d12.dll`、`apd12.dll`、`kernelbase.dll`，校验并确定性地修改 CrossOver 的 stock `kernelbase.dll`，再把用户选择的 GPTK 4.x `external` 安装进一份完整应用快照。这里不包含闭源 shim 源码，也不声称从头重建了它。

工具不会自动启动原补丁工具，不下载任何组件，不执行 pkg 安装器。`check` 只读；只有显式 `install` 才写入，并在失败时自动回滚。

## 前置条件

- macOS，Python 3.12+，CrossOver **26.3.0**，win64 bottle。
- 用户本机的 GPTK 4.x `external`，包含 `libd3dshared.dylib` 与 `D3DMetal.framework`；framework 版本必须为 4.x。
- 用户提供的 FH4 补丁工具 `.app`，内含三份 PE DLL。DLL 只在本地导入到被 Git 忽略的 `payloads/`。
- 安装/回滚前关闭所有 Wine/CrossOver 程序；Endfield 等正在运行的会话会被检测并拒绝操作。

## 用法

```sh
# 从用户提供的 app 导入三份 DLL（逐个 SHA-256 与导出校验）
./install.sh import-payloads "$HOME/Downloads/地平线4补丁工具.app"

# 只读预检：不写 app/bottle/注册表，不要求空闲
./install.sh check \
  --app "$HOME/Applications/CrossOver.app" \
  --bottle "$HOME/Library/Application Support/CrossOver/Bottles/FH4" \
  --gptk-external "/path/to/GPTK-4.x/external"

# 显式安装；backup 路径必须尚不存在
./install.sh install \
  --app "$HOME/Applications/CrossOver.app" \
  --bottle "$HOME/Library/Application Support/CrossOver/Bottles/FH4" \
  --gptk-external "/path/to/GPTK-4.x/external" \
  --backup "$HOME/FH4-FineWine-backup" \
  --fh4-exe "$HOME/.../ForzaHorizon4.exe" \
  --fh4-sha256 "<该构建的 SHA-256>" \
  --allow-unverified-game

# 所有构建均尚未验证 VEH；即使提供哈希也必须明确选择
./install.sh install ... --allow-unverified-game

# 按备份恢复 app、bottle 文件、环境变量与 DllOverride
./install.sh rollback "$HOME/FH4-FineWine-backup"
```

`install` 会写入：

- 应用内 `kernelbase.dll`（仅从已知 stock 哈希生成）、Apple GPTK `x86_64-windows` 下的 `d3d12.dll`/`apd12.dll`、`x86_64-unix/apd12.so` 链接；
- bottle `drive_c/windows/system32` 下的三份 DLL；
- 仅目标 FH4 bottle 的 `cxbottle.conf` 中写入 `D3DM_VENDOR_ID=0x8086`、`D3DM_DEVICE_ID=0x56a1`、`D3DM_DEVICE_DESCRIPTION=Intel(R) Arc(TM) A750 Graphics`，保留 `WINEMSYNC` 和其他未管理项；
- bottle `user.reg` 的最小 `DllOverrides` 修改：`"apd12"="builtin"`（CrossOver 启动器会删除 `WINEDLLOVERRIDES`，因此必须写注册表）；
- 最后执行 ad-hoc 签名并验证。

提供 EXE 和 SHA-256 只能固定文件身份，不能验证 VEH 的固定地址适配；目前没有已验证的 FH4 构建。`--allow-unverified-game` 是明确接受这一未知风险的选择。

回滚恢复 app 快照、bottle 文件、`cxbottle.conf` 和 `apd12` 覆盖的原值。备份在回滚成功后会保留 manifest 以支持恢复；确认不再需要时可手动删除。

其他子命令：

```sh
# 确定性 kernelbase 补丁；输出路径必须不存在
./install.sh patch-kernelbase /path/to/stock/kernelbase.dll /path/to/kernelbase-patched.dll

# 只读检查载荷：哈希、导入、导出序号、COFF 模块/函数名
./install.sh inspect payloads/d3d12.dll payloads/apd12.dll
```

## 已验证与未验证

**已在隔离副本中验证**：CrossOver 26.3.0.39832、D3DMetal 4.0b3；`d3d12` 装载与 11 个导出、`apd12` builtin 装载、`apd12.so` 链接、`D3D12CreateDevice` 返回 `S_OK` 且产生非空设备、ad-hoc 签名、安装/`--replace`/回滚、失败注入恢复、注册表原值恢复。

**未验证**：没有目标 FH4 可执行文件，因此没有游戏启动、进入世界、渲染正确性、帧率或稳定性结论；没有安装进用户正在使用的 CrossOver/Endfield；固定 RVA VEH 在真实游戏版本上的效果未知；没有供应商签名。

上述三项伪装显卡变量仅写入用户明确指定的 FH4 bottle。D3DMetal 4.0b3 framework 的静态字符串包含这三个变量名，但本项目没有验证 DXGI 实际枚举出的适配器名称/ID，也没有据此宣称 FH4 可玩或视频设置兼容；工具不修改游戏 video 设置。

详见 [兼容性矩阵](docs/compatibility.md)、[来源记录](docs/PROVENANCE.md)、[隔离验证日志](docs/verification.md)、[复现步骤](docs/reproduce.md) 与现场交接 [HANDOFF.md](HANDOFF.md)。
