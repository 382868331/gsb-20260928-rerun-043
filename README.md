# 临床研究数据平台（第一版）

面向临床研究数据管理的 Python 标准库实现。第一版聚焦**虚构研究资料**的去标识导出：
先把研究批次、字段规则和导出版本管起来；统计分析是后续阶段，本版不接入任何医院系统。

## 目录

- `crp/batch.py`：研究批次与字段规则管理，规则更新完整留痕；
- `crp/pseudonym.py`：受试者伪名与按人固定日期偏移，映射只保存在 `data/private/`；
- `crp/redact.py`：内置敏感模式 + `manual_sensitive.json` 人工标注片段脱敏；
- `crp/exporter.py`：按规则去标识并生成不可变导出版本；
- `crp/audit.py`：泄露扫描与跨表受试者引用一致性核对；
- `data/raw/STUDY-001/`：完全虚构的人口学、访视、检验、用药四类记录；
- `configs/`：批次配置与第二版字段规则示例。

## 去标识策略

- **直接身份字段移除**：姓名、身份证号、电话、地址等整列 `drop`；
- **日期按人固定偏移**：每位受试者由批次密钥确定性派生一个偏移（-90~90 天），
  该受试者在所有表上的日期共用同一偏移，保留随访间隔与相对时序；
- **受试者伪名**：真实编号经 HMAC 派生为稳定伪名，跨人口学/访视/检验/用药表一致，
  导出后仍可按伪名做跨表关联；
- **自由文本脱敏**：对主诉、备注等字段同时处理身份证、手机号、邮箱等内置模式，
  以及人工补录的人名、地址等片段，替换为 `[REDACTED]`。

映射与批次密钥存放在 `data/private/<batch>/mapping.json`，仅供内部审计，
**不会写入 `data/exports/` 的任何公开版本**；导出完成后自动扫描公开文件确认无真实编号、
人工敏感片段或内置敏感模式残留。

## 使用

```bash
python -m crp init-batch --config configs/study001.json
python -m crp export STUDY-001 --note 'v1：基线去标识规则'
python -m crp verify STUDY-001
python -m crp export STUDY-001   # 规则/数据未变：幂等复用同一版本并做字节级核对

# 更新字段规则后再导出：生成 v002，v001 与其版本说明原样保留
python -m crp update-rules STUDY-001 --rules configs/study001_rules_v2.json \
    --note 'v2：删除人口学备注并补充用药日期平移'
python -m crp export STUDY-001 --note 'v2：删除人口学备注并补充用药日期平移'
python -m crp preview-scope STUDY-001 --scope-json '{"sources":["medications"]}'
python -m crp update-rules STUDY-001 --rules configs/study001_rules_v2.json \
    --note 'v3：仅用药资料' --scope-json '{"sources":["medications"]}'
python -m crp versions STUDY-001

# 比较两次导出在规则内容、适用范围、输入数据、最终内容四个维度上的变化
python -m crp compare STUDY-001 1 2

# 沿规则修订顺序查看每次执行：标注配置相同/输出相同/同一次执行重跑/内容复用
python -m crp rule-trail STUDY-001

# 按接收者核对多次交付合在一起会公开什么（联合披露预览）
python -m crp register-recipient STUDY-001 REC-A --name '某医院科研科'
# request 声明冻结的导出版本与本次申请的记录（record_id 取自 rule_trace.csv）
python -m crp disclosure-preview STUDY-001 REC-A \
    --request-json '{"version":1,"records":[{"table":"labs","record_id":"labs:visit_id=V001;test_code=LDL"}]}' \
    --output preview.json
python -m crp confirm-disclosure STUDY-001 REC-A --preview preview.json --plan as_requested --note '第一次：检验'
# 政策修订（禁止字段/字段组合）只约束今后的新交付，历史交付不改写
python -m crp revise-policy STUDY-001 \
    --rules-json '{"forbid_combinations":[{"fields":["visit_date","department"]}]}' --note '禁止日期+科室'
# 同一接收者两份申请可以同时待审：保存后按申请 ID 做联合预览（含其他待审申请）
python -m crp submit-application STUDY-001 REC-A APP-LABS \
    --request-json '{"version":1,"date_precision":"month","records":[{"table":"labs","record_id":"labs:visit_id=V001;test_code=LDL"}]}' \
    --note '月精度检验'
python -m crp submit-application STUDY-001 REC-A APP-VISITS \
    --request-json '{"version":1,"records":[{"table":"visits","record_id":"visits:visit_id=V001"}]}' \
    --note '就诊资料'
python -m crp applications STUDY-001 REC-A
python -m crp disclosure-preview STUDY-001 REC-A --application APP-VISITS --output preview.json
# 先确认其中一份后，另一份的旧预览立即过期，必须重新预览（会基于已交付的实际内容核对）
python -m crp confirm-disclosure STUDY-001 REC-A --preview preview.json --plan cancel  # 取消不登记
# 接收者授权缩小同样只影响此后的交付
python -m crp narrow-authorization STUDY-001 REC-A \
    --scope-json '{"sources":["labs"]}' --note '缩小到检验来源'
python -m crp deliveries STUDY-001 REC-A
```

默认数据根目录为 `./data`，可用全局参数 `--data-root` 修改。

## 版本与核对

- 执行身份由**本次真正生效的规则修订号与原始数据指纹**唯一确定：同一规则修订 + 同一份原始数据
  的重复导出（含中断后重试）是幂等的，复用同一执行版本并用 SHA-256 校验已发布文件未被改动；
  规则即使改回历史上出现过的旧配置（v1→v2→回到 v1 配置成为 v3），由于修订号已前进，
  仍会产生全新的独立执行，绝不用历史执行冒充当前执行；
- 规则修订或原始数据任一变化都会产生新的执行版本目录 `exports/<batch>/v00N/`，内含 CSV 与
  `manifest.json`（本次真正生效的规则版本、版本说明、规则/数据/输出指纹、文件校验值）；
  即使去标识后最终字节恰好与旧版本完全一致（例如规则调整未实际触发任何替换），
  也不会把执行身份合并到旧版本，而是在 manifest 中以 `content_reused_from` 标注内容来源版本；
- 旧版本目录、旧版本说明与 `data/private/` 中的伪名/日期偏移映射永不覆盖、继续可查；
- 规则修订可声明 `scope`，支持 `sources`、`subjects`、`time_range.fields`、`records`；导出按最新命中修订向旧修订回退，范围外沿用旧规则；
- 每次导出写入公开 `rule_trace.csv`，逐行记录来源行、输出行、伪名、业务记录键、规则修订号、适用范围与采用依据；
- 扩大或缩小适用范围产生新执行；旧 manifest、旧轨迹和旧采用范围不改写；新增来源记录在执行当时重新判定；
  历史目录迁移后即使丢失索引，也能从不可变版本目录重建 `index.json`；
- `compare vA vB` 分别报告规则内容变化、适用范围变化、输入数据变化、最终内容变化，并明确区分三个层次：
  **配置相同**（规则指纹一致但修订号可以不同）、**公开输出相同**（字节一致但属不同执行）、
  **属于同一次执行**（规则修订号与输入均一致，即幂等重跑），同时列出新增/删除/内容变化的文件；
- `rule-trail` 沿规则修订顺序列出全部执行，逐条标注「规则配置退回/重复」「公开输出与上一版相同」
  「同一次执行重跑」与「内容复用自 v00N」；
- `verify` 检查直接标识列、真实受试者号、人工敏感片段、敏感模式，并列出跨表关联到同一伪名的记录。

## 按接收者的联合披露核对

去标识导出版本是面向所有接收者的候选公开结果；`crp/disclosure.py` 在其上增加「接收者维度」：

- **接收者档案与授权修订**（`disclosure/<batch>/recipients/`）：每个接收者独立登记，授权范围
  只增不改；后来缩小授权只影响之后的交付，之前收到什么仍有准确记录；
  同时待审的资料申请保存在 `disclosure/<batch>/applications/<recipient>.json`，按接收者隔离；
- **不可变对外材料**（`disclosure/<batch>/materials/Mxxxx/`）：由冻结的导出版本、记录选择、
  日期精度与来源别名确定性派生（材料 ID 即其规格指纹）；保存或网络重试辨认出同一份材料时
  复用同一 `material_id`，只累加 `attempts`，绝不重复计入披露；
- **预览绑定身份**：每次预览绑定接收者、导出版本（资料身份）、授权修订、政策修订与
  既有交付快照；预览生成后既有交付增加（或授权/政策/导出变化），确认时判为过期，必须重新核对；
  确认时还要核对接收者与资料身份一致，不能拿 A 的预览向 B 交付；
- **关联依据分级，不靠猜测**：逐条记录标注与既有交付的对应——`record_key`（业务记录键可确认，
  来源改名时必须提供显式 `source_aliases` 才成立）、`subject`（业务键对不上但同一稳定伪名的
  受试者级确定关联）、`unconfirmed`（来源改名且无别名等依据，记录级对应只标注、不参与新增组合计算）；
  同一记录在新导出版本中再次出现、字段经过不同变换（如更细日期精度）都会如实列出；
- **新增公开内容**：逐字段标注是否首次可被该接收者关联到（`newly_linkable`）、日期精度是否
  较既往升级，并汇总跨既有交付的 `new_combination`；
- **四种方案对比**：`as_requested`（全部，撞政策时确认被拦截）、`allow_only`（剔除授权外/政策禁止
  的字段或记录）、`reduce_precision`（日期降至月，重新计算仍成立的组合）、`cancel`（不形成材料），
  每种方案各自列出仍会新增的可关联内容与采用规则；
- **同时待审申请的联合核对**：申请可用 `submit-application` 保存为待审状态（落盘，重开可继续），
  `disclosure-preview --application <id>` 不仅核对既有交付，还把**同一接收者其他待审申请**视为
  「若都获批将一并公开」，逐条列出 `pending_combination`（与待审同伴的新组合）并按政策做
  **跨申请联合组合判定**：各申请单独看都安全、但合在一起可关联出日期+科室+检验时，`as_requested`
  确认被拦截，且无论按什么顺序确认都绕不过；`blocked` 条目带 `cross_union` 依据说明字段来自哪份
  已交付材料或待审申请；
- **精度决定组合是否成立**：跨来源精确关联要求组合中的日期字段最终都以日精度公开。月精度检验与
  日精度就诊资料同时待审时不构成精确组合（但仍如实列出联合后可关联内容）；其中一份先交付后，
  另一份的旧预览**立即失效**，必须重审，且重审依据的是**实际交付**的精度（月），而不是申请设想；
  后续再申请把同一检验提升到日精度时，会重新形成与已交付就诊资料的精确组合并被拦截；
- **取消不登记、确认留痕、接收者隔离**：`cancel` 方案与 `cancel-application` 把待审申请直接移除，
  不形成材料、不留申请登记；确认后申请标记为 `confirmed` 并记录交付 ID；政策/授权修订只影响今后
  的预览与交付，不改写旧材料与历史登记；待审申请、交付登记与联合快照全部按接收者分文件保存，
  不同接收者的历史与待审互不可见；
- **内外有别**：`audit_note` 等内部审计说明（可含真实编号）只写入内部交付登记
  `disclosure/<batch>/deliveries/<recipient>.json`，绝不进入对外材料目录；材料目录整体经过
  真实编号、人工敏感片段与内置敏感模式扫描（`scan_material_leaks`）。

## 路线图

- 后续阶段在去标识导出之上增加统计分析模块（只消费 `exports/` 公开数据）；
- 可扩展更多字段动作与跨表业务外键（如 `visit_id`）的一致性约束。
