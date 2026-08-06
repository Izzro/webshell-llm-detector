# WebShell LLM Detector

基于大语言模型的脚本类恶意代码识别研究 — 检测系统

## 项目简介

本项目通过调用云端大语言模型 API（DeepSeek / 通义千问），利用提示词工程实现 Web 场景下脚本类恶意代码的识别。不训练模型，纯静态文本分析。

## 环境要求

- Python 3.10+
- DeepSeek API Key（环境变量 `DEEPSEEK_API_KEY`）
- 阿里云百炼 API Key（环境变量 `DASHSCOPE_API_KEY`）

## 快速开始

### 1. 安装依赖

```bash
cd webshell-llm-detector
pip install -r requirements.txt
```

### 2. 配置环境变量

**Windows PowerShell（临时）：**
```powershell
$env:DEEPSEEK_API_KEY = "你的DeepSeek密钥"
$env:DASHSCOPE_API_KEY = "你的百炼密钥"
```

**Windows（永久）：**
```powershell
[System.Environment]::SetEnvironmentVariable("DEEPSEEK_API_KEY", "你的密钥", "User")
[System.Environment]::SetEnvironmentVariable("DASHSCOPE_API_KEY", "你的密钥", "User")
```

### 3. 验证 API 连通性

```bash
python scripts/verify_api.py
```

### 4. 阶段一：数据集构建

```bash
# 收集良性样本
python scripts/collect_benign.py

# 收集恶意样本
python scripts/collect_malicious.py

# 生成混淆变种
python scripts/generate_obfuscated.py

# 生成标签文件
python scripts/create_labels.py

# 数据集统计
python scripts/dataset_stats.py
```

## 项目结构

```
webshell-llm-detector/
├── config.yaml                # 全局配置（API、路径、参数）
├── requirements.txt           # 依赖清单
├── src/                       # 核心源码模块
│   ├── llm_client.py          # LLM API 调用封装
│   ├── sample_loader.py       # 样本加载器
│   ├── prompt_templates.py    # 提示词模板（3组策略）
│   ├── result_parser.py       # 结果解析器
│   ├── metrics.py             # 指标计算
│   ├── exporter.py            # 数据导出
│   └── batch_runner.py        # 批量检测主流程
├── scripts/                   # 阶段一脚本
│   ├── verify_api.py          # API 连通性验证
│   ├── collect_benign.py      # 良性样本收集
│   ├── collect_malicious.py   # 恶意样本收集
│   ├── generate_obfuscated.py # 混淆变种生成
│   ├── create_labels.py       # 标签文件生成
│   └── dataset_stats.py       # 数据集统计
├── data/
│   ├── samples/               # 样本文件（按类别组织）
│   └── labels.csv             # 样本标签索引
├── results/                   # 实验结果输出
└── tests/                     # 测试
```

## 安全声明

- 所有样本仅做静态文本读取和分析，**禁止执行任何恶意代码**
- API 密钥通过环境变量管理，不硬编码在源码中
- 实验数据必须真实可复现
