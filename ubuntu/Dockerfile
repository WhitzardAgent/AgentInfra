FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.local/bin:${PATH}"

# Install necessary system packages: python3, pip, venv, bash
RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-venv bash && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy your local MCP server source code into /app/ubuntu_mcp_server in the image
COPY ubuntu_mcp_server /app/ubuntu_mcp_server

# Create Python virtual environment and install dependencies
RUN python3 -m venv /app/ubuntu_mcp_server/.venv && \
    /bin/bash -c "source /app/ubuntu_mcp_server/.venv/bin/activate && pip install --upgrade pip && pip install -r /app/ubuntu_mcp_server/requirements.txt"

WORKDIR /app/ubuntu_mcp_server

# Replace 9000 with the actual port your MCP server listens on:
EXPOSE 9000

# Start the MCP server using virtual environment python
CMD ["/bin/bash", "-c", "source /app/ubuntu_mcp_server/.venv/bin/activate && exec python main.py"]