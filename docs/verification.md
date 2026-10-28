# 隔离验证日志（2026-10-28）

以下为 CrossOver 26.3 应用副本 + 私有 win64 bottle + GPTK 4.0b3 `external` 的关键输出摘要。路径做了缩写；未在 `/Applications/CrossOver.app` 或 Endfield bottle 上执行。

## 1. `apd12` 默认 native 解析失败

```text
trace:module:load_dll looking for L"apd12.dll" in L"C:\\;C:\\windows\\system32;..."
trace:module:get_load_order_value got standard key n for L"apd12"
warn:module:load_dll Failed to load module L"apd12.dll"; status=c0000135
```

同一文件复制为 `foo.dll` 后 native 装载并取到 `D3D12CreateDevice`，退出码 0；因此失败与 PE 内容无关。

## 2. 持久 builtin 覆盖后装载成功

`user.reg`：

```text
[Software\\Wine\\DllOverrides]
"apd12"="builtin"
"d3d12"="native,builtin"
```

装载/取址探针（无命令行 override）：

```text
wine --bottle <bottle> --scope private --cx-app 'C:\fh4probe.exe'
exit=0
```

## 3. `D3D12CreateDevice` ABI 探针

调用约定：`rcx=NULL`、`edx=0xb000`、`r8=&IID_D3D12Device`、`r9=&out`。第一版把 `out` 放在只读 `.rdata`，异常为写 `0x140002120` 的访问冲突：

```text
dispatch_exception code=c0000005 (EXCEPTION_ACCESS_VIOLATION)
info[0]=1 info[1]=0000000140002120
```

改为栈上可写 `out` 后：

```text
wine ... --cx-app 'C:\fh4probe_call.exe'
exit=0   # S_OK 且 out 非空
```

## 4. 安装、替换、回滚

```text
Creating complete application snapshot; this may take time.
Installed. FH4 loading and gameplay remain unverified. Backup: <backup-2>

Restored app snapshot and bottle files from <backup-2>
state=installed        # 恢复到上一次 installed 状态，apd12 仍为 builtin

Restored app snapshot and bottle files from <backup>
state=pristine         # 手动恢复安装前 user.reg 后，apd12=native
```

`codesign --verify --all-architectures --deep --strict` 在安装结束时通过。

## 5. 单元测试

```text
python3.13 -m unittest discover -s tests
Ran 22 tests
OK (skipped=1)
```

跳过项为需要 `FH4_STOCK_KERNEL` 的真实 26.3 stock 测试；有本地 payloads 时载荷清单测试会执行。
