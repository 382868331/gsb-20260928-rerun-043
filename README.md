# 临床研究数据平台（第一版）

面向临床研究数据管理的 Python 标准库实现。第一版聚焦**虚构研究资料**的去标识导出：
先把研究批次、字段规则和导出版本管起来；统计分析是后续阶段，本版不接入任何医院系统。

## 目录

- `crp/batch.py`：研究批次与字段规则管理，规则更新完整留痕；
- `crp/pseudonym.py`：受试者伪名与按人固定日期偏移，映射只保存在 `data/private/`；
- `crp/redact.py`：内置敏感模式 + `manual_sensitive.json` 人工标注片段脱敏；
- `crp/exporter.py`：按规则去标识并生成不可变导出版本；
- `crp/audit.py`：泄露扫描与跨表受试者引用一致性核对；
- `crp/disclosure.py`：按接收者登记授权与交付，预览多次交付合在一起的联合披露；
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

## 按接收者的联合披露预览

导出版本是面向所有接收者的候选公开结果；真正发给谁、发过什么，在 `disclosure.py` 这一层按
**接收者**单独记账，核心原则是「不能只看本次文件，要核对同一接收者多次交付合在一起会公开什么」：

- **绑定身份**：每份预览绑定明确的接收者、冻结的导出版本（资料身份）和该接收者当时的既有交付范围；确认时若接收者不符直接拒绝；
- **关联依据有据可查**：本次每条记录都会列出能对应到的既有交付，依据分为 `record_key`（业务记录键加伪名可确认）、`subject`（同一稳定伪名的受试者级关联）与 `unconfirmed`（来源改名且未用 `source_aliases` 声明显式别名，记录级对应缺少依据）；缺少依据的对应只列出、不参与新增组合计算，绝不靠猜测补出记录关系；
- **新增可关联组合**：逐字段标注既往是否已对该受试者公开、日期是否从月升级到日，并列出本次记录与既往记录合在一起后新能关联出的字段组合（`new_combination`、`new_field`、`subject_links`）；
- **政策只管今后**：`revise-policy` 可声明 `forbid_fields` 与 `forbid_combinations`，禁止此后新增的字段或字段组合，但历史交付登记与材料永不改写；接收者用 `narrow-authorization` 追加授权修订（通常缩小范围），也只影响之后的交付；
- **三种可比方案**：预览同时给出 `as_requested`（全量，撞政策直接拒绝确认）、`allow_only`（仅交付授权与政策允许的部分，剔除受限字段或记录）、`reduce_precision`（日期统一降至月精度）与 `cancel`（取消），每个方案都列出仍会新增的可关联内容、阻止项及采用的授权/政策修订号；
- **过期不可提交**：预览带快照（授权修订、政策修订、导出版本指纹、既有交付清单）。确认前若既有交付增加（或授权/政策/导出版本变化），确认被拒绝，必须重新核对后再提交；
- **同一份材料不重复计入**：对外材料由「导出版本、记录选择、日期精度、来源别名或改名」确定性派生材料 ID；保存与重试若形成同一份对外材料（字节一致），复用材料目录、交付登记只增加 `attempts`，不会重复计入披露；
- **审计说明与公开结果分离**：`audit_note` 只写入内部交付登记（`data/disclosure/<batch>/deliveries/`），材料目录（`materials/`）整体经过与导出同级的泄露扫描，真实编号、人工敏感片段、证件/手机/邮箱模式都不能因为「保留审计说明」进入公开结果。

相关命令：`register-recipient`、`narrow-authorization`、`revise-policy`、`disclosure-preview`（可用 `--output` 保存带快照的预览 JSON）、`confirm-disclosure`（`--plan` 取 `as_requested`、`allow_only`、`reduce_precision`、`cancel`）、`deliveries`。`disclosure-preview` 的请求 JSON 形如 `{"version":1,"records":[{"table":"labs","record_id":"labs:visit_id=V001;test_code=LDL"}],"source_names":{"labs":"laboratory_results"},"source_aliases":{"labs":"labs"}}`；来源改名时只有在 `source_aliases` 中显式声明，记录级对应才被视为可确认。

## 路线图

- 后续阶段在去标识导出之上增加统计分析模块（只消费 `exports/` 公开数据）；
- 可扩展更多字段动作与跨表业务外键（如 `visit_id`）的一致性约束。
