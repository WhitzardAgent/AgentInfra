#!/usr/bin/env bash
set -e

# 可通过环境变量覆盖
IMG=${IMG:-android-with-mcp:11}
NAME=${NAME:-android-container-mcp-test}
DEVICE_NAME=${DEVICE_NAME:-"Samsung Galaxy S10"}
MCP_PORT=${MCP_PORT:-10000}

# 检查镜像是否存在
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "[error] image '$IMG' not found. 请先运行 ./build_docker.sh"
  exit 1
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true

docker run -d --name "$NAME" --restart unless-stopped \
  --device /dev/kvm \
  -e EMULATOR_DEVICE="$DEVICE_NAME" \
  -e WEB_VNC=true \
  -p 6080:6080 \
  -p 5554:5554 \
  -p 5555:5555 \
  -p ${MCP_PORT}:${MCP_PORT} \
  "$IMG"

# # 如果容器已存在：已运行→复用；已退出→启动；不存在→新建
# if docker ps -a --format '{{.Names}}' | grep -q "^${NAME}$"; then
#   if docker ps --format '{{.Names}}' | grep -q "^${NAME}$"; then
#     echo "[info] container '$NAME' 已在运行，跳过创建"
#   else
#     echo "[info] 启动已存在的容器 '$NAME'"
#     docker start "$NAME" >/dev/null
#   fi
# else
#   echo "[run] 创建并启动容器 '$NAME'"
#   docker run -d --name "$NAME" --restart unless-stopped \
#     --device /dev/kvm \
#     -e EMULATOR_DEVICE="$DEVICE_NAME" \
#     -e WEB_VNC=true \
#     -p 6080:6080 \
#     -p 5554:5554 \
#     -p 5555:5555 \
#     -p ${MCP_PORT}:${MCP_PORT} \
#     "$IMG" >/dev/null
# fi

echo "[info] 等待模拟器就绪（adb 设备 + boot_completed=1）..."
docker exec -it "$NAME" bash -lc '
  adb start-server >/dev/null 2>&1 || true
  # 等待设备出现
  for i in {1..120}; do
    if adb devices | awk "NR>1 && \$2==\"device\"" | grep -q device; then break; fi
    sleep 2
  done
  # 等待系统引导完成
  for i in {1..120}; do
    if adb shell getprop sys.boot_completed 2>/dev/null | grep -q 1; then break; fi
    sleep 2
  done
  echo "[ok] emulator booted"
'

# 安装 DeviceKit（已装会跳过）
# docker exec -it "$NAME" bash -lc '
#   if ! adb shell pm path com.mobilenext.devicekit >/dev/null 2>&1; then
#     echo "[info] 安装 DeviceKit ..."
#     if [ -f /opt/devicekit.apk ]; then
#       adb install -r /opt/devicekit.apk || true
#     else
#       curl -fsSL -o /tmp/devicekit.apk https://github.com/mobile-next/devicekit-android/releases/download/0.0.10/mobilenext-devicekit.apk && \
#       adb install -r /tmp/devicekit.apk || true
#     fi
#   fi
# '

# # 启动 MCP（若已在跑则跳过）
# docker exec -it "$NAME" bash -lc '
#   # if pgrep -fa "@mobilenext/mobile-mcp" >/dev/null 2>&1; then
#   #   echo "[info] MCP 已在运行，跳过"
#   # else
#   echo "[info] 启动 MCP（端口：'"$MCP_PORT"'）"
#   nohup npx -y @mobilenext/mobile-mcp --port '"$MCP_PORT"' >/var/log/mobile-mcp.out 2>&1 &
#   # fi
# '

# 启动 MCP
# docker exec -u 0 -it "$NAME" bash -lc '
#   echo "[info] 启动 MCP（端口：'"$MCP_PORT"'）"
#   nohup exec npx -y @mobilenext/mobile-mcp --port '"$MCP_PORT"' >/var/log/mobile-mcp.out 2>&1 &
# '

# 启动 MCP
docker exec -u 0 -d "$NAME" \
  /usr/bin/npx -y @mobilenext/mobile-mcp --port "${MCP_PORT}"

echo "[info] waiting MCP (SSE) to be ready on :${MCP_PORT} ..."
sleep 2
echo "[info] 启动 MCP（端口：'"$MCP_PORT"'）"


echo
echo "[ready] 打开 noVNC:    http://<服务器IP>:6080"
echo "[ready] MCP (SSE):     http://<服务器IP>:${MCP_PORT}/mcp"
echo "[tip]  查看日志:       docker logs -f ${NAME}"
echo "[tip]  进入容器:       docker exec -u 0 -it ${NAME} bash"
