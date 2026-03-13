#!/usr/bin/env bash
# AI-Reverse 一键环境安装脚本
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPS_DIR="$PROJECT_DIR/deps"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# 结果跟踪
RESULTS=()
record() { RESULTS+=("$1"); }

# ============================================
# 1. 检查前置依赖
# ============================================
log_info "检查前置依赖..."

check_command() {
    local cmd=$1
    local name=${2:-$1}
    local install_hint=${3:-""}
    if command -v "$cmd" &>/dev/null; then
        local ver
        ver=$("$cmd" --version 2>&1 | head -1)
        log_ok "$name: $ver"
        record "  ✅ $name"
        return 0
    else
        log_error "$name 未安装"
        [ -n "$install_hint" ] && log_info "  安装方法: $install_hint"
        record "  ❌ $name (未安装)"
        return 1
    fi
}

DEPS_OK=true
check_command python3 "Python3" "brew install python3 / apt install python3" || DEPS_OK=false
check_command java "Java" "brew install openjdk@17 / apt install openjdk-17-jdk" || DEPS_OK=false
check_command adb "ADB" "brew install android-platform-tools / apt install adb" || DEPS_OK=false
check_command uv "uv" "pip install uv / curl -LsSf https://astral.sh/uv/install.sh | sh" || DEPS_OK=false
check_command pip3 "pip3" "通常随 Python3 安装" || DEPS_OK=false
check_command git "Git" "brew install git / apt install git" || DEPS_OK=false

if [ "$DEPS_OK" = false ]; then
    log_warn "部分依赖缺失，继续安装可能遇到问题"
    read -p "是否继续? (y/N) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
fi

# ============================================
# 2. 安装 Frida 工具链
# ============================================
log_info "安装 Frida 工具链..."

if pip3 install frida-mcp frida-tools 2>/dev/null; then
    log_ok "frida-mcp 和 frida-tools 安装成功"
    record "  ✅ frida-mcp"
    record "  ✅ frida-tools"
else
    log_warn "frida-mcp 安装失败，尝试使用 --user 选项..."
    if pip3 install --user frida-mcp frida-tools 2>/dev/null; then
        log_ok "frida-mcp 和 frida-tools 安装成功 (--user)"
        record "  ✅ frida-mcp (user)"
        record "  ✅ frida-tools (user)"
    else
        log_error "frida-mcp 安装失败"
        record "  ❌ frida-mcp"
    fi
fi

# ============================================
# 3. 克隆 MCP Server 仓库
# ============================================
log_info "克隆 MCP Server 仓库..."
mkdir -p "$DEPS_DIR"

clone_repo() {
    local repo_url=$1
    local target_dir=$2
    local name=$3

    if [ -d "$target_dir" ]; then
        log_info "$name 已存在，执行 git pull..."
        (cd "$target_dir" && git pull --quiet) && log_ok "$name 更新成功" || log_warn "$name 更新失败"
    else
        log_info "克隆 $name..."
        if git clone --quiet "$repo_url" "$target_dir"; then
            log_ok "$name 克隆成功"
        else
            log_error "$name 克隆失败"
            record "  ❌ $name"
            return 1
        fi
    fi
    record "  ✅ $name"
}

clone_repo "https://github.com/zinja-coder/jadx-mcp-server.git" "$DEPS_DIR/jadx-mcp-server" "jadx-mcp-server"
clone_repo "https://github.com/zinja-coder/apktool-mcp-server.git" "$DEPS_DIR/apktool-mcp-server" "apktool-mcp-server"

# ============================================
# 4. 安装 MCP Server 依赖
# ============================================
log_info "安装 MCP Server 依赖..."

# jadx-mcp-server 依赖
if [ -f "$DEPS_DIR/jadx-mcp-server/requirements.txt" ]; then
    pip3 install -r "$DEPS_DIR/jadx-mcp-server/requirements.txt" 2>/dev/null && \
        log_ok "jadx-mcp-server 依赖安装成功" || \
        log_warn "jadx-mcp-server 依赖安装失败"
fi

# apktool-mcp-server 依赖 (使用 uv)
if [ -f "$DEPS_DIR/apktool-mcp-server/pyproject.toml" ]; then
    (cd "$DEPS_DIR/apktool-mcp-server" && uv sync 2>/dev/null) && \
        log_ok "apktool-mcp-server 依赖安装成功" || \
        log_warn "apktool-mcp-server 依赖安装失败"
elif [ -f "$DEPS_DIR/apktool-mcp-server/requirements.txt" ]; then
    pip3 install -r "$DEPS_DIR/apktool-mcp-server/requirements.txt" 2>/dev/null && \
        log_ok "apktool-mcp-server 依赖安装成功" || \
        log_warn "apktool-mcp-server 依赖安装失败"
fi

# ============================================
# 5. 从模板生成 .mcp.json（幂等操作）
# ============================================
log_info "生成 .mcp.json 配置..."

MCP_TEMPLATE="$PROJECT_DIR/.mcp.json.template"
MCP_JSON="$PROJECT_DIR/.mcp.json"
JADX_PATH="$DEPS_DIR/jadx-mcp-server"
APKTOOL_PATH="$DEPS_DIR/apktool-mcp-server"

if [ -f "$MCP_TEMPLATE" ]; then
    # 始终从模板重新生成，保证幂等
    if [[ "$(uname)" == "Darwin" ]]; then
        sed "s|__JADX_MCP_PATH__|${JADX_PATH}|g; s|__APKTOOL_MCP_PATH__|${APKTOOL_PATH}|g" "$MCP_TEMPLATE" > "$MCP_JSON"
    else
        sed "s|__JADX_MCP_PATH__|${JADX_PATH}|g; s|__APKTOOL_MCP_PATH__|${APKTOOL_PATH}|g" "$MCP_TEMPLATE" > "$MCP_JSON"
    fi
    log_ok ".mcp.json 已从模板生成"
    record "  ✅ .mcp.json 配置"

    # 验证生成的文件中不再包含占位符
    if grep -q '__.*_PATH__' "$MCP_JSON"; then
        log_warn ".mcp.json 中仍含有未替换的占位符"
    fi

    # 验证入口文件是否存在
    for entry_file in "$JADX_PATH/jadx_mcp_server.py" "$APKTOOL_PATH/apktool_mcp_server.py"; do
        if [ ! -f "$entry_file" ]; then
            log_warn "入口文件不存在: $entry_file"
        fi
    done
else
    log_error ".mcp.json.template 未找到"
    record "  ❌ .mcp.json 配置"
fi

# ============================================
# 6. 验证工具可用性
# ============================================
log_info "验证工具可用性..."

# 验证 frida-mcp
if command -v frida-mcp &>/dev/null; then
    log_ok "frida-mcp 可用"
else
    log_warn "frida-mcp 不在 PATH 中，可能需要重启终端"
fi

# 验证 frida
if command -v frida &>/dev/null; then
    FRIDA_VER=$(frida --version 2>/dev/null)
    log_ok "frida 版本: $FRIDA_VER"
else
    log_warn "frida CLI 不可用"
fi

# 验证 adb 连接
if adb devices 2>/dev/null | grep -q "device$"; then
    log_ok "ADB 设备已连接"
else
    log_warn "未检测到 ADB 设备（动态分析需要连接设备）"
fi

# ============================================
# 7. 输出安装摘要
# ============================================
echo ""
echo "============================================"
echo -e "${GREEN}  AI-Reverse 环境安装完成${NC}"
echo "============================================"
echo ""
echo "安装结果:"
for r in "${RESULTS[@]}"; do
    echo "$r"
done
echo ""
echo "项目目录: $PROJECT_DIR"
echo "依赖目录: $DEPS_DIR"
echo ""
echo "下一步:"
echo "  1. 确保 Android 设备已连接并运行 frida-server"
echo "  2. 在 Claude Code 中打开项目: cd $PROJECT_DIR"
echo "  3. 使用 /android-re 触发逆向工程 Skill"
echo ""
echo "常用命令:"
echo "  frida-ps -U                    # 列出设备进程"
echo "  frida -U -f <包名> -l <脚本>    # spawn 模式注入脚本"
echo "  frida -U -n <进程名> -l <脚本>  # attach 模式注入脚本"
echo ""
