# 🛡️ Auto PoC (Burp Suite Extension)

> **Auto PoC** 是一款用于 Burp Suite 的自动化 PoC（概念验证）重放工具。

## 📖 简介 / Introduction

**Auto PoC** 旨在简化安全测试流程。它能够自动监听 HTTP 请求，智能提取 JSON 请求体中的特定参数，并追加预设的 Payload 进行重放，从而快速验证潜在的安全漏洞（如 XSS、SQLi 等）。


## ⚙️ 配置选项 / Configuration

插件右侧面板提供了灵活的配置功能：

| 选项名称 | 说明 |
| :--- | :--- |
| **Target Domain** | **目标域名过滤**<br>若填写（如 `example.com`），插件仅处理该域名的请求；<br>若留空，则处理所有经过 Burp 的请求。 |
| **Target Params** | **目标参数名**<br>指定需要注入 Payload 的 JSON Key。<br>支持多个参数，使用竖线 `\|` 分隔。<br>例如：`name\|user\|account` |
| **Fuzzy Match** | **模糊匹配开关**<br>🔴 **关闭 (Default)**：仅当 JSON Key 与目标参数**完全一致**时才注入。<br>🟢 **开启**：只要 JSON Key **包含**目标参数字符串即注入。<br>*(例如：设置 `name` 可匹配 `username`, `nickname`)* |
| **PoC Payload** | **攻击载荷**<br>Payload 将被追加到原始参数值的后面。<br>例如：`<img src=x onerror=alert(1)>` |
| **Enable Plugin** | **插件总开关**<br>🔘 **默认关闭 (False)**：防止加载插件后立即发送意外请求。<br>✅ **勾选后**：立即开始监听流量并执行重放任务。 |
| **Clear Logs** | **清空日志**<br>清除当前的记录列表和计数器。 |


## 🧠 工作原理 / Core Logic

Auto PoC 遵循以下逻辑对流量进行处理：

1.  **请求筛选** 🔍
    * 仅处理 HTTP 方法为 **`POST`** 或 **`PUT`** 的请求。
    * 仅解析并处理 **JSON 格式** 的 Request Body。

2.  **递归注入** 💉
    * 插件会自动递归遍历复杂的嵌套 JSON 结构（包括字典 `dict` 和列表 `list`）。
    * 查找与 `Target Params` 匹配的 Key。

3.  **注入模式** 📝
    * 采用追加模式：`New Value = Original Value + Payload`。

4.  **结果反馈** 📊
    * **🟢 绿色背景**：重放请求的响应状态码为 **`200`**。
    * **⚪ 白色背景**：重放请求的响应状态码为 **非 200**。


## 🚀 使用步骤 / Usage

1.  **安装插件**：在 Burp Suite 的 Extender 中加载本插件。
2.  **配置参数**：切换到 **Auto PoC** 标签页，在右侧面板设置：
    * 目标域名 (`Target Domain`)
    * 目标参数 (`Target Params`)
    * 测试 Payload (`PoC Payload`)
3.  **开启监听**：勾选右侧的 **"Enable Plugin"** 复选框。
4.  **触发请求**：在浏览器中正常访问业务，或在 Burp Repeater 中发送请求。
5.  **查看结果**：
    * 观察左侧日志列表。
    * 点击任意条目，下方会自动分栏显示该次重放的 **Request** 和 **Response**，便于同屏对比。


## 📦 Installation

1.  确保 Burp Suite 已安装 **Jython** 环境。
2.  下载本仓库的 Python 文件。
3.  打开 Burp Suite -> **Extensions** -> **Add**。
4.  Extension type 选择 **Python**，Select file 选择下载的代码文件。


*Disclaimer: This tool is for educational and authorized testing purposes only.*
