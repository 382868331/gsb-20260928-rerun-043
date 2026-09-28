# 临床研究数据平台（Python 第一版：去标识导出）

面向虚构（离线）研究资料的最小可用平台。第一版只做**研究批次管理、字段规则管理、导出版本管理与去标识导出**；统计分析在后续版本再加入。**不对接任何医院系统**，全部输入来自本地 CSV 文件。

## 解决的核心问题

1. **直接身份字段移除**：`drop` 动作的列（姓名、身份证号、手机号）不会出现在导出中。
2. **日期按受试者固定偏移**：每个受试者有一个确定性的、对所有表所有日期一致的平移量（`-180..179` 天），由项目私有盐 HMAC 派生；同一受试者跨就诊、检验、用药的时间间隔保持不变。
3. **自由文本中的人工敏感片段不遗漏**：
   - 规则中登记的姓名、科室、住址等短语一律替换为 `[REDACTED]`；
   - 未登记但形如身份证号、手机号、座机、邮箱的片段用内置正则兜底；
   - 导出前对全部公开文件做一次“原始 ID / 敏感短语是否逐字出现”的终检，发现即拒绝导出。
4. **跨表关联一致**：受试者 ID 在整个批次内映射为稳定伪名（如 `P9CD15E0DBC219739`），人口学/就诊/检验/用药四类记录共享同一映射；导出版本提供跨表引用核对。
5. **版本不可变、旧说明保留**：每次导出写入 `exports/<batch>/v000001/`、`v000002/`……永不覆盖；规则也独立版本化，每个导出锁定当时的规则版本与说明。
6. **映射不进公开结果**：原始 ID→伪名、日期偏移只保存在 `.crp-private/mappings/`（目录 `0700`、文件 `0600`）；公开 `manifest.json` 只给出敏感词*数量*，不含词表本身。

## 目录布局

```
.crp-private/                 # 私有，0700，不随导出共享
  salt                        # 项目私有盐
  batches/<batch>.json        # 批次元数据与版本说明历史
  rules/<batch>/rules-v*.json # 规则的完整私有快照（含敏感词表）
  raw/<batch>/*.csv           # 导入的原始 CSV（0600）
  mappings/<batch>.json       # 原始ID↔伪名、日期偏移（0600）
  versions/<batch>/v*.json    # 每次导出的私有元数据
exports/<batch>/v000001/      # 可共享：去标识 CSV + manifest.json
```

## 字段规则动作

每列必须显式声明，**未声明的新列会导致导出报错**（避免新身份列意外泄露）：

| 动作 | 含义 |
| --- | --- |
| `keep` | 原样保留（仅限非敏感数据） |
| `drop` | 直接身份字段，整列移除 |
| `subject_id` | 替换为批次内稳定伪名 |
| `date` | 按受试者固定偏移平移，保留输入日期写法（`YYYY-MM-DD` / `YYYY/MM/DD` / `YYYYMMDD`） |
| `text` | 自由文本：敏感短语 + 证件/手机号/邮箱模式扫描替换 |

示例见 `examples/rules-demo.json`，虚构资料见 `examples/sample_data/`（同一受试者横跨四类记录，文本中故意埋入手机、邮箱、他人身份证号）。

## 快速开始

```bash
python -m venv .venv && . .venv/bin/activate   # 可选
pip install -e .                                # 或直接用 PYTHONPATH

crp init
crp batch demo --title '虚构队列'
crp rules demo examples/rules-demo.json
for t in demographics visits labs medications; do
  crp import demo $t examples/sample_data/$t.csv
done
crp export demo --note '首次去标识导出'
crp verify-refs demo --version 1       # 跨表引用核对

# 规则更新后再导出：旧版本与旧说明原样保留
$EDITOR examples/rules-demo.json       # 增加敏感词或调整字段
crp rules demo examples/rules-demo.json
crp export demo --note '规则更新后重导'
crp reconcile demo --old 1 --new 2     # 重复导出核对（新增/消失受试者、逐文件差异）
crp versions demo                      # 查看全部版本说明
```

## 核对口径

- `verify-refs`（跨表引用）：各表伪名必须都能在锚表 `demographics` 找到，且同一受试者在所有表只有一个伪名；发现孤立伪名返回非零退出码。
- `reconcile`（重复导出）：比较两个不可变版本，输出新增/消失受试者、共同受试者数量及逐文件差异；规则与数据都未变时数据文件逐字节一致、伪名与日期偏移稳定。

## 边界（第一版）

- 仅离线 CSV，单进程本地使用；不做采集对接、权限系统或统计分析。
- 去标识是规则化处理，不能保证应对所有重识别攻击；发布前仍需由数据治理人员复核。
- 日期为整体平移，不做泛化（如按月截断）；需要时在后续版本扩展规则动作。

## 测试

```bash
python -m pytest -q
```

覆盖：私有/公开目录隔离、身份列移除、文本与模式脱敏、同受试者伪名与日期偏移跨表一致、日期写法保留、重复导出稳定性、规则更新保留旧版本说明、未声明列拒绝导出、跨表孤立引用检测。
