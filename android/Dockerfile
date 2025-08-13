FROM budtmo/docker-android:emulator_11.0

# 仅在构建期用 root 安装 Node；不动上游入口
USER root
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# 安装 Node.js 22（NodeSource）+ 基础工具
RUN apt-get update && \
    apt-get install -y curl ca-certificates gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# （可选）预下 DeviceKit（下载失败也不阻塞；运行时还能再装）
ARG DEVICEKIT_URL="https://github.com/mobile-next/devicekit-android/releases/download/0.0.10/mobilenext-devicekit.apk"
RUN mkdir -p /opt && (curl -fsSL "$DEVICEKIT_URL" -o /opt/devicekit.apk || true)

# 关键：把运行用户切回镜像默认（避免家目录/权限假设失效）
USER androidusr