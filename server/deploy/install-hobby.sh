#!/usr/bin/env bash
# ============================================================
# wgp-node-hobby 一键部署脚本（家庭宽带贡献版 · Debian/Ubuntu 系）
#
# 原则：脚本不写死任何端口/地址等部署参数——
#   - 默认参数由二进制自持（07 §6 规格：bind 0.0.0.0:11010 + stun 3478 + tcp 3481）
#   - 需要覆盖时改 /etc/wgp-node/env（键见 wgp-node.env.example）
#   - 防火墙请另行执行 server/deploy/wgp-node.nft（见 DEPLOY.md §2），
#     本脚本不代劳：nft 文件首行 flush ruleset 会清空宿主机全部规则
#
# 用法：先 cargo build --release，然后 sudo bash server/deploy/install-hobby.sh
# 可用环境变量覆盖安装位置（不覆盖则用下方默认值）：
#   WGP_INSTALL_DIR  安装目录（默认 /opt/wgp-node）
#   WGP_RUN_USER     服务运行用户（默认 wgp）
#   WGP_ENV_FILE     环境文件路径（默认 /etc/wgp-node/env）
#   WGP_BIN          二进制来源（默认 <仓库>/target/release/wgp-node-hobby）
# ============================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_DIR="${WGP_INSTALL_DIR:-/opt/wgp-node}"
RUN_USER="${WGP_RUN_USER:-wgp}"
ENV_FILE="${WGP_ENV_FILE:-/etc/wgp-node/env}"
BIN_SRC="${WGP_BIN:-$REPO_ROOT/target/release/wgp-node-hobby}"
BIN_DST="$INSTALL_DIR/wgp-node-hobby"
UNIT_SRC="$REPO_ROOT/server/deploy/wgp-node-hobby.service"
ENV_SRC="$REPO_ROOT/server/deploy/wgp-node.env.example"

[ "$(id -u)" -eq 0 ] || { echo "[错误] 请用 sudo 运行"; exit 1; }
[ -x "$BIN_SRC" ] || { echo "[错误] 缺少 $BIN_SRC —— 先执行 cargo build --release"; exit 1; }
[ -f "$UNIT_SRC" ] || { echo "[错误] 缺少 $UNIT_SRC"; exit 1; }
[ -f "$ENV_SRC" ] || { echo "[错误] 缺少 $ENV_SRC"; exit 1; }

# 1) 服务用户（系统用户，无登录 shell）
id -u "$RUN_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$RUN_USER"

# 2) 二进制与目录
mkdir -p "$INSTALL_DIR" "$(dirname "$ENV_FILE")"
install -m 0755 "$BIN_SRC" "$BIN_DST"
chown "$RUN_USER:$RUN_USER" "$INSTALL_DIR"

# 3) 环境文件：已存在则绝不动（运维调过的配置是生产资产），仅首次从模板创建
if [ -f "$ENV_FILE" ]; then
    echo "[跳过] $ENV_FILE 已存在，不覆盖"
else
    install -m 0640 -o root -g "$RUN_USER" "$ENV_SRC" "$ENV_FILE"
    echo "[完成] $ENV_FILE <- 模板（全注释，即全用默认值）"
fi

# 4) systemd 单元 + 启动
install -m 0644 "$UNIT_SRC" /etc/systemd/system/wgp-node-hobby.service
systemctl daemon-reload
systemctl enable --now wgp-node-hobby
sleep 1
systemctl --no-pager -l status wgp-node-hobby | head -n 12 || true

echo
echo "[下一步]"
echo "  防火墙：sudo nft -f $REPO_ROOT/server/deploy/wgp-node.nft && sudo systemctl enable --now nftables"
echo "  改参数：编辑 $ENV_FILE（去掉注释）→ systemctl restart wgp-node-hobby"
echo "  看日志：journalctl -u wgp-node-hobby -f   # 出现『已就绪（种子+观察者+承诺兜底）』即成功"
echo "  自检：  journalctl -u wgp-node-hobby | grep node_id   # 重启后 node_id 应不变（身份持久化）"
