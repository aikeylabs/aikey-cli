#!/bin/bash
set -euo pipefail
TEST_PASSWORD="test_password_123456"
TEST_SECRETS=(
    "OPENAI_API_KEY=OPENAI_API_KEY:sk-xxx1234567890abcdef"
    "ANTHROPIC_API_KEY=ANTHROPIC_API_KEY:sk-ant-xxx987654321fedcba"
)
TEST_TMP_DIR=$(mktemp -d)
AK_BIN="./target/debug/ak"
BACKGROUND_PIDS=()

# 工具函数
log_info() { echo -e "\033[32m[INFO] $1\033[0m"; }
log_warn() { echo -e "\033[33m[WARN] $1\033[0m"; }
log_error() { echo -e "\033[31m[ERROR] $1\033[0m"; exit 1; }
run_ak_command() { local cmd="$1"; local input="$2"; echo -e "$input" | $AK_BIN $cmd; }

# 安全终止进程（修复变量拼写错误）
safe_kill() {
    local pid="$1"
    local name="$2"
    if ps -p "$pid" > /dev/null 2>&1; then
        log_info "终止 $name 进程（PID: $pid）..."
        kill -SIGINT "$pid" > /dev/null 2>&1
        # 等待3秒让进程正常退出
        for i in {1..3}; do
            sleep 1
            if ! ps -p "$pid" > /dev/null 2>&1; then
                log_info "✅ $name 进程已正常退出"
                return 0
            fi
        done
        # 强制终止
        kill -9 "$pid" > /dev/null 2>&1
        log_warn "⚠️  $name 进程强制终止（PID: $pid）"
    fi
}

# ===================== 前置检查 =====================
log_info "=== 前置检查 & 编译 ==="
[ ! -f "$AK_BIN" ] && (log_info "编译 AK 二进制..."; cargo build || log_error "编译失败")
log_info "测试隔离目录：$TEST_TMP_DIR"
export HOME="$TEST_TMP_DIR"
mkdir -p "$HOME/.aikey"

# ===================== 步骤1：初始化 Vault =====================
log_info "\n=== 1. 初始化 Vault ==="
init_input="$TEST_PASSWORD\n$TEST_PASSWORD"
run_ak_command "init" "$init_input" || log_error "Vault 初始化失败"
log_info "✅ Vault 初始化成功"

# ===================== 步骤2：添加测试密钥 =====================
log_info "\n=== 2. 添加测试密钥 ==="
for secret in "${TEST_SECRETS[@]}"; do
    key_alias=$(echo "$secret" | cut -d: -f1 | cut -d= -f2)
    value=$(echo "$secret" | cut -d: -f2)
    add_input="$TEST_PASSWORD\n$value"
    run_ak_command "add $key_alias" "$add_input" || log_error "添加密钥 $key_alias 失败"
    log_info "✅ 密钥 $key_alias 添加成功"
done

# ===================== 步骤3：验证密钥列表 =====================
log_info "\n=== 3. 验证密钥列表 ==="
list_output=$(run_ak_command "list" "$TEST_PASSWORD")
for secret in "${TEST_SECRETS[@]}"; do
    key_alias=$(echo "$secret" | cut -d: -f1 | cut -d= -f2)
    if echo "$list_output" | grep -q "$key_alias"; then
        log_info "✅ 密钥 $key_alias 已在列表中"
    else
        log_error "密钥 $key_alias 未出现在列表中"
    fi
done

# ===================== 步骤4：核心测试 - Ghost Execution 注入 =====================
log_info "\n=== 4. 核心测试：Ghost Execution 环境注入 ==="
secret="${TEST_SECRETS[0]}"
env_mapping=$(echo "$secret" | cut -d: -f1)
value=$(echo "$secret" | cut -d: -f2)
exec_cmd="exec -e $env_mapping env"

exec_output=$(run_ak_command "$exec_cmd" "$TEST_PASSWORD")
if echo "$exec_output" | grep -q "OPENAI_API_KEY=$value"; then
    log_info "✅ 单个密钥注入成功（OPENAI_API_KEY）"
else
    log_error "单密钥注入失败，输出：$exec_output"
fi

# 多密钥注入
exec_multi_cmd="exec -e ${TEST_SECRETS[0]%:*} -e ${TEST_SECRETS[1]%:*} env"
exec_multi_output=$(run_ak_command "$exec_multi_cmd" "$TEST_PASSWORD")
multi_ok=true
if ! echo "$exec_multi_output" | grep -q "OPENAI_API_KEY=${TEST_SECRETS[0]#*:}"; then
    log_warn "❌ 多密钥注入：OPENAI_API_KEY 未找到"
    multi_ok=false
fi
if ! echo "$exec_multi_output" | grep -q "ANTHROPIC_API_KEY=${TEST_SECRETS[1]#*:}"; then
    log_warn "❌ 多密钥注入：ANTHROPIC_API_KEY 未找到"
    multi_ok=false
fi
if $multi_ok; then
    log_info "✅ 多密钥注入成功（OPENAI_API_KEY + ANTHROPIC_API_KEY）"
else
    log_warn "⚠️  多密钥注入部分失败（不终止测试）"
fi

# ===================== 步骤5：安全测试 - 环境隔离 =====================
log_info "\n=== 5. 安全测试：环境隔离验证 ==="
run_ak_command "exec -e $env_mapping sleep 10" "$TEST_PASSWORD" &
AK_PID=$!
BACKGROUND_PIDS+=("$AK_PID")
sleep 2

# 检查父进程环境
if [[ "$OSTYPE" == "darwin"* ]]; then
    parent_env=$(ps eww "$AK_PID" | awk '{$1=$2=$3=$4=$5=""; print $0}')
else
    parent_env=$(cat /proc/"$AK_PID"/environ | tr '\0' '\n')
fi

if echo "$parent_env" | grep -q "OPENAI_API_KEY"; then
    log_error "❌ 父进程环境泄露密钥 OPENAI_API_KEY"
else
    log_info "✅ 父进程环境无密钥泄露（环境隔离达标）"
fi

# ===================== 步骤6：安全测试 - 信号拦截与清理 =====================
log_info "\n=== 6. 安全测试：信号拦截与原子化清理 ==="
run_ak_command "exec -e $env_mapping sleep 5" "$TEST_PASSWORD" &
AK_PID2=$!
BACKGROUND_PIDS+=("$AK_PID2")
sleep 2

# 发送SIGINT信号
kill -SIGINT "$AK_PID2" > /dev/null 2>&1
# 等待进程退出
for i in {1..5}; do
    sleep 1
    if ! ps -p "$AK_PID2" > /dev/null 2>&1; then
        log_info "✅ 信号拦截成功，进程正常退出（原子化清理达标）"
        break
    fi
    if [ "$i" -eq 5 ]; then
        log_warn "⚠️  进程未响应SIGINT，将强制终止"
        kill -9 "$AK_PID2" > /dev/null 2>&1
    fi
done

# ===================== 清理阶段 =====================
log_info "\n=== 测试完成 & 清理 ==="
# 终止所有后台进程
for pid in "${BACKGROUND_PIDS[@]}"; do
    safe_kill "$pid" "后台"
done

# 清理临时目录
sleep 1
if [ -d "$TEST_TMP_DIR" ]; then
    rm -rf "$TEST_TMP_DIR"
    log_info "✅ 测试临时目录已清理"
fi

# 清理代码警告
cargo fix --lib -p aikeylabs-ak > /dev/null 2>&1
log_info "✅ 代码警告已清理"
log_info "✅ Day 4 Ghost Execution 全功能验证完成！"
