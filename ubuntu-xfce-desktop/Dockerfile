# 基础镜像
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:1
ENV RESOLUTION=1280x800

# 安装基本组件 + pyautogui 依赖
RUN apt-get update && apt-get install -y \
    xfce4 xfce4-goodies x11vnc xvfb \
    firefox wget curl net-tools sudo git \
    python3 python3-venv python3-pip supervisor \
    python3-tk scrot xdotool socat gnome-screenshot wmctrl ffmpeg xclip\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# 创建用户
RUN useradd -m docker && echo "docker:docker" | chpasswd && adduser docker sudo

# 下载 noVNC 和 websockify（源码）
WORKDIR /opt
RUN git clone https://github.com/novnc/noVNC /opt/noVNC \
    && git clone https://github.com/novnc/websockify /opt/websockify \
    && chmod +x /opt/websockify/run

# 设置 VNC 密码
RUN mkdir -p /home/docker/.vnc \
    && x11vnc -storepasswd 123456 /home/docker/.vnc/passwd

# 复制 MCP server 代码
COPY ubuntu_mcp_server /app/ubuntu_mcp_server
WORKDIR /app/ubuntu_mcp_server

# 创建 Python 虚拟环境并安装依赖
RUN python3 -m venv .venv && \
    /bin/bash -c "source .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt"

# 复制 supervisord 配置文件
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# 公开端口
EXPOSE 6080 9000

# 启动 supervisord
CMD ["/usr/bin/supervisord", "-n"]
