---
name: template-rendering
description: 将报告数据安全地渲染为可编辑Word、PDF和配套数据包。
---

# 模板渲染

## 步骤

1. 验证模板 ID、版本和适用报告类型。
2. 检查必填字段和图片、图表、表格数据。
3. 渲染 DOCX，必要时生成 PDF。
4. 检查目录、标题层级、表格宽度、分页、页眉页脚和字体替换。
5. 检查敏感字段、占位符、空章节和断裂引用。
6. 输出 report.docx、report.pdf、report-data.json、evidence-manifest.json 和 source-manifest.json。

## 规则

模板只决定表现，不得修改事实、数字和风险状态。渲染失败必须保留结构化数据并返回明确错误。
