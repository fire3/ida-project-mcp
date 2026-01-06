# IDA Project MCP

本文档定义一组 MCP 工具接口，用于对“项目中的一组二进制逆向数据”进行查询、反汇编/反编译、交叉引用、图分析与检索，以支撑自动化分析与人机协同研判。

## 通用约定

### 标识与地址

- `project`: 项目标识（字符串）。
- `binary`: 二进制标识（字符串）。建议为稳定的 `binary_id`（而非仅文件名），并可在返回结构中同时提供 `display_name` / `path`。
- `address`: 地址（十六进制字符串，建议形如 `"0x401000"`）。
- `range`: 地址范围对象 `{ start_address, end_address }`，均为 `address`。

- `list_*`: 列表类查询接口。
- `search_*`: 搜索类查询接口。
- `get_*`: 获取类查询接口。

### 分页与排序

- `offset`: 从 0 开始的偏移。
- `limit`: 返回条数上限（建议默认 50，最大 500）。
- `order_by`: 排序字段（如 `address` / `name` / `score`）。
- `order`: `asc | desc`。

### 返回与错误

- 所有工具建议统一返回对象：`{ ok: boolean, data?: any, error?: { code: string, message: string, details?: any } }`
- 建议错误码：
  - `NOT_FOUND`（project/binary/address 不存在或不可映射）
  - `INVALID_ARGUMENT`（参数不合法）
  - `UNSUPPORTED`（该二进制/架构/后端不支持此能力）
  - `ANALYSIS_NOT_READY`（需要先索引/分析）
  - `RATE_LIMITED`（限流）
  - `INTERNAL_ERROR`（内部错误）

### 后端能力探测

- 由于不同逆向后端（IDA / Ghidra / BinaryNinja / 自研解析器）能力差异较大，建议提供“能力枚举”接口，调用侧可据此选择降级策略。

## 基础信息（Project / Binary）

- **`get_project_overview`**
  - **功能**: 获取项目概览（包含二进制数量、索引状态、后端类型等）。
  - **参数**: `project` (字符串，可选；为空则返回默认/当前项目)。
  - **返回**: 项目概览对象（含 `binaries_count` / `analysis_status` / `capabilities` 等）。

- **`get_project_binaries`**
  - **功能**: 获取项目中的所有二进制文件。
  - **参数**: `project` (字符串，可选), `offset` (整数，可选), `limit` (整数，可选), `filters` (对象，可选：如 `format`/`arch`/`os`/`has_symbols`)。
  - **返回**: 二进制列表（建议包含 `binary`、`display_name`、`format`、`arch`、`bits`、`hashes`、`image_base`、`entry_points` 等）。

- **`get_binary_metadata`**
  - **功能**: 获取指定二进制的元数据。
  - **参数**: `binary` (字符串)。
  - **返回**: 元数据字典（建议包含：文件格式、架构/位宽/端序、哈希、编译器推断、是否剥离符号、加载基址、入口点、导入导出数量、段/节数量、时间戳等）。

- **`get_backend_capabilities`**
  - **功能**: 返回当前后端可用能力与限制（便于调用侧分支处理）。
  - **参数**: `project` (字符串，可选), `binary` (字符串，可选)。
  - **返回**: 能力对象（如 `decompile`/`cfg`/`callgraph`/`type_system`/`patching`/`demangle` 等布尔或版本信息）。

## 装载视图（Segments / Sections / Symbols）

- **`list_binary_sections`**
  - **功能**: 获取节区（section）列表与属性。
  - **参数**: `binary` (字符串)。
  - **返回**: section 列表（名称、虚拟地址、大小、权限、文件偏移、熵、类型等）。

- **`list_binary_segments`**
  - **功能**: 获取段（segment）列表与属性（如果后端区分 segment/section）。
  - **参数**: `binary` (字符串)。
  - **返回**: segment 列表。

- **`list_binary_imports`**
  - **功能**: 获取导入表（含导入库、符号、IAT/PLT 地址等）。
  - **参数**: `binary` (字符串), `offset` (整数，可选), `limit` (整数，可选)。
  - **返回**: import 列表（建议包含 `library`、`name`、`ordinal`、`address`、`thunk_address` 等）。

- **`list_binary_exports`**
  - **功能**: 获取导出表（函数/变量）。
  - **参数**: `binary` (字符串), `offset` (整数，可选), `limit` (整数，可选)。
  - **返回**: export 列表（建议包含 `name`、`ordinal`、`address`、`forwarder` 等）。

- **`list_binary_symbols`**
  - **功能**: 获取符号（含本地/全局/调试符号，按后端能力）。
  - **参数**: `binary` (字符串), `query` (字符串，可选), `offset` (整数，可选), `limit` (整数，可选)。
  - **返回**: symbol 列表（建议包含 `name`、`kind`、`address`、`size`、`demangled_name` 等）。

- **`resolve_address`**
  - **功能**: 将地址解析为“所在函数/符号/段节/字符串/指令”等上下文。
  - **参数**: `binary` (字符串), `address` (十六进制字符串)。
  - **返回**: 上下文对象（如 `function`、`symbol`、`section`、`is_code`、`is_data`、`string_ref` 等）。

## 数据读取

- **`get_binary_bytes`**
  - **功能**: 读取指定虚地址处的原始字节，并格式化二进制数据（类似 `od` 命令）。
  - **参数**: `binary` (字符串), `address` (十六进制字符串), `length` (整数), `format_type` (字符串，如 `"x1"`, `"c"`, `"d4"` 等)
  - **返回**: 格式化后的数据文本。

- **`get_binary_decoded_data`**
  - **功能**: 获取某地址处的结构化数据信息（IDA构建的数据信息，非原始二进制数据）。
  - **参数**: `binary` (字符串), `address` (十六进制字符串)，`length` (整数)。
  - **返回**: 指令对象（含 `address`、`size`、`mnemonic`等）。

## 反汇编
- **`get_binary_disassembly_text`**
  - **功能**: 获取指定地址范围的反汇编结果。
  - **参数**: `binary` (字符串), `start_address` (十六进制字符串), `end_address` (十六进制字符串)  
  - **返回**: 指令列表或反汇编文本。

- **`get_binary_function_disassembly_text`**
  - **功能**: 获取指定地址范围的反汇编结果。
  - **参数**: `binary` (字符串), `function_address` (十六进制字符串) 。
  - **返回**: 指令列表或反汇编文本。


## 函数与反编译

- **`get_binary_functions`**
  - **功能**: 列出二进制中的函数（可筛选/搜索）。
  - **参数**: `binary` (字符串), `query` (字符串，可选：按名称/签名模糊匹配), `offset` (整数，可选), `limit` (整数，可选), `filters` (对象，可选：`is_thunk`/`is_library`/`has_decompile`)。
  - **返回**: 函数列表（建议包含 `name`、`address`、`size`、`prototype?`、`flags?`）。

- **`get_binary_function_by_name`**
  - **功能**: 根据名称查找函数。
  - **参数**: `binary` (字符串), `names` (字符串或字符串列表), `match` (字符串，可选：`exact|prefix|contains|regex`，默认 `exact`)。
  - **返回**: 函数信息列表（名称、地址、大小、原型等）。

- **`get_binary_function_by_address`**
  - **功能**: 根据地址查找所属函数。
  - **参数**: `binary` (字符串), `addresses` (十六进制字符串或列表)。
  - **返回**: 函数信息列表（名称、地址、大小、原型等）。

- **`get_binary_function_pseudo_code_by_address`**
  - **功能**: 获取指定函数的反编译伪代码。
  - **参数**: `binary` (字符串), `addresses` (十六进制字符串或列表), `options` (对象，可选：`with_types`/`with_comments`/`max_lines`/`language`(默认 `c`))。
  - **返回**: 伪代码结果列表（建议结构化：`{ function_address, name, pseudo_code, warnings? }`）。

## 调用关系与交叉引用

- **`get_binary_function_callees`**
  - **功能**: 获取指定函数调用的被调用者（callee）。
  - **参数**: `binary` (字符串), `function_address` (十六进制字符串), `depth` (整数，可选：默认 1), `limit` (整数，可选)。
  - **返回**: 被调用函数列表（建议含 `call_site_address`、`callee_address`、`callee_name?`、`call_type`）。

- **`get_binary_function_callers`**
  - **功能**: 获取调用指定函数的调用者（caller）。
  - **参数**: `binary` (字符串), `function_address` (十六进制字符串), `depth` (整数，可选：默认 1), `limit` (整数，可选)。
  - **返回**: 调用者函数列表（建议含 `call_site_address`、`caller_address`、`caller_name?`）。

- **`get_binary_cross_references_to_address`**
  - **功能**: 获取对指定地址的交叉引用（Xref To）。
  - **参数**: `binary` (字符串), `address` (十六进制字符串), `offset` (整数，可选), `limit` (整数，可选), `filters` (对象，可选：`code_only`/`data_only`)。
  - **返回**: 引用列表（建议含 `from_address`、`from_function?`、`xref_type`、`operand_index?`）。

- **`get_binary_cross_references_from_address`**
  - **功能**: 获取从指定地址发出的交叉引用（Xref From）。
  - **参数**: `binary` (字符串), `address` (十六进制字符串), `offset` (整数，可选), `limit` (整数，可选)。
  - **返回**: 引用列表（建议含 `to_address`、`to_function?`、`xref_type`）。

## 字符串与常量检索

- **`list_binary_strings`**
  - **功能**: 枚举二进制中的字符串（含 ASCII/UTF-16/UTF-8，按后端能力）。
  - **参数**: `binary` (字符串), `query` (字符串，可选), `min_length` (整数，可选), `encodings` (字符串列表，可选), `offset` (整数，可选), `limit` (整数，可选)。
  - **返回**: 字符串列表（建议含 `address`、`string`、`encoding`、`length`、`section`）。

- **`get_string_xrefs`**
  - **功能**: 获取对某字符串地址的引用（快速定位使用点）。
  - **参数**: `binary` (字符串), `string_address` (十六进制字符串), `offset` (整数，可选), `limit` (整数，可选)。
  - **返回**: 引用列表（建议含 `from_address`、`from_function?`、`xref_type`）。

- **`search_string_symbol_in_binary`**
  - **功能**: 在二进制中查找指定字符串。
  - **参数**: `binary` (字符串), `search_string` (字符串), `match` (字符串，可选：`contains|exact|regex`，默认 `contains`)。
  - **返回**: 匹配字符串信息列表（建议与 `get_binary_strings` 一致）。

- **`search_immediates_in_binary`**
  - **功能**: 搜索立即数/常量在代码中的使用位置（例如 magic number、错误码、端口号）。
  - **参数**: `binary` (字符串), `value` (整数或十六进制字符串), `width` (整数，可选：8/16/32/64), `offset` (整数，可选), `limit` (整数，可选)。
  - **返回**: 使用点列表（建议含 `address`、`function_address?`、`instruction`）。

- **`search_bytes_pattern_in_binary`**
  - **功能**: AOB/字节模式搜索（支持通配符）。
  - **参数**: `binary` (字符串), `pattern` (字符串，如 `"48 8B ?? ?? ?? 89"`), `offset` (整数，可选), `limit` (整数，可选)。
  - **返回**: 匹配地址列表（建议含置信度或匹配长度）。

## 工程级检索（Project-Wide）

- **`search_string_symbol_in_project`**
  - **功能**: 在项目中查找所有包含指定字符串的二进制与位置。
  - **参数**: `search_string` (字符串), `match` (字符串，可选：`contains|exact|regex`), `offset` (整数，可选), `limit` (整数，可选)。
  - **返回**: 命中列表（建议为扁平结构：`[{ binary, hits: [...] }]` 或直接 `[{ binary, address, string, ... }]`）。

- **`search_exported_function_in_project`**
  - **功能**: 在项目中查找导出指定函数名称的二进制（动态库/可执行文件）。
  - **参数**: `function_name` (字符串), `match` (字符串，可选：`exact|contains|regex`), `offset` (整数，可选), `limit` (整数，可选)。
  - **返回**: 命中列表（建议包含 `binary`、`export`(name/address/ordinal)）。

- **`search_similar_functions_in_project`**
  - **功能**: 按函数特征相似度在项目内检索（需要索引能力）。
  - **参数**: `binary` (字符串), `function_address` (十六进制字符串), `top_k` (整数，可选：默认 20), `threshold` (浮点，可选)。
  - **返回**: 相似函数列表（含 `binary`、`function_address`、`score`、`method`）。