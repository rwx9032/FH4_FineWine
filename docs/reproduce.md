# 从载荷复现安装与验证

本流程不联网、不执行 pkg、不修改正在使用的 CrossOver。准备：

- CrossOver 26.3 应用与一个 win64 bottle；
- GPTK 4.x Evaluation 的 `external`（含 `libd3dshared.dylib`、`D3DMetal.framework`）；
- 用户提供的原补丁工具 `.app` 或其中三份 DLL。

## 1. 导入并校验载荷

```sh
./install.sh import-payloads "$HOME/Downloads/地平线4补丁工具.app"
```

期望：`d3d12.dll` `bc9d…1a44`、`apd12.dll` `f1bc…976f`、`kernelbase.dll` `313a…0f182`。

```sh
./install.sh inspect payloads/d3d12.dll payloads/apd12.dll
```

期望：各 11 个导出、序号 100–110；`d3d12.dll` 的 COFF 模块含 `d3d12.c`，`apd12.dll` 的函数名含 `ne_init_unix_call`。

## 2. 复现 kernelbase 补丁

```sh
./install.sh patch-kernelbase <stock-26.3>/kernelbase.dll /tmp/kernelbase-patched.dll
```

stock SHA-256 必须为 `ca72a76ce5770996cc9cba6989031a79eb1e63b6d9fca90d59eebab22e39191b`；输出必须为 `313a9d07019422fe0f56a579667d005d756728e13b66329aaa15321d92b0f182`，差异 135 字节。

## 3. 离线测试

```sh
python3.13 -m unittest discover -s tests -v
```

期望 `OK`；无载荷时相关测试自动 skip。

## 4. 在副本上安装（推荐）

先复制 app 与 bottle 到临时位置，确保不在使用中：

```sh
./install.sh check --app <copy>/CrossOver.app --bottle <copy-bottle> \
  --gptk-external <external> --allow-unverified-game
./install.sh install --app <copy>/CrossOver.app --bottle <copy-bottle> \
  --gptk-external <external> --backup <new-backup> --allow-unverified-game
```

期望：写入 3 个 app DLL、`apd12.so` 链接、bottle system32 三份 DLL、`cxbottle.conf` 环境块、`user.reg` 的 `"apd12"="builtin"`，签名验证通过，`state=installed`。

## 5. 回滚

```sh
./install.sh rollback <new-backup>
```

期望：app 快照、bottle 文件、环境块、`apd12` 原值恢复；若安装前为 stock，则 `check` 报告 `state=pristine`。

## 6. 运行边界

以上步骤验证的是装载链、ABI、签名和事务性，不是游戏可玩性。真实 FH4 需要：

```sh
./install.sh install ... --fh4-exe <ForzaHorizon4.exe> --fh4-sha256 <sha> \
  --backup <new-backup>
```

并在可回滚副本中记录启动/世界加载/崩溃/帧率；不要把 `--allow-unverified-game` 的结果当成已完成游戏验证。
