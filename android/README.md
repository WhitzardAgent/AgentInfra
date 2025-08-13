1. If it is you first time using this docker image, you need to build it, otherwise you can skip this step.
```bash
chmod +x build_docker.sh
./build_docker.sh
```

2. Run the docker image.
```bash
chmod +x start.sh
./start.sh
```

3. Waiting for the docker image to start.
```bash
[info] 等待模拟器就绪（adb 设备 + boot_completed=1）...
[ok] emulator booted
[info] 启动 MCP（端口：'10000'）

[ready] 打开 noVNC:    http://<服务器IP>:6080
[ready] MCP (SSE):     http://<服务器IP>:10000/mcp
[tip]  查看日志:       docker logs -f android-container-mcp-test
[tip]  进入容器:       docker exec -u 0 -it android-container-mcp-test bash
```