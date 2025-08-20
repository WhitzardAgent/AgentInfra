FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.local/bin:${PATH}"



# Create a new user (e.g., 'myuser')
RUN useradd -m -s /bin/bash myuser




RUN apt-get update && \
    apt-get install -y \
      python3 python3-pip python3-venv bash curl gnupg \
      build-essential sudo netcat && \
    # Install Node.js 20.x + npm
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create sandbox user
RUN useradd -m -s /bin/bash sandbox
# Add 'myuser' to the sudoers group
RUN usermod -aG sudo sandbox
# (Optional) Allow passwordless sudo (for convenience in container)
RUN echo "sandbox ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers


WORKDIR /env

# Copy MCP source code
COPY ubuntu_mcp_server /env/ubuntu_mcp_server
COPY verify.py /env/verify.py
# Set permissions to sandbox
RUN chown -R sandbox:sandbox /env

USER sandbox

# Create Python virtual env and install dependencies
RUN python3 -m venv /env/ubuntu_mcp_server/.venv && \
    /bin/bash -c "source /env/ubuntu_mcp_server/.venv/bin/activate && pip install --upgrade pip && pip install -r /env/ubuntu_mcp_server/requirements.txt"

WORKDIR /env/ubuntu_mcp_server

# Expose MCP server port and supergateway port
EXPOSE 9000 9001

# Start both MCP server and supergateway
# Use a shell script to manage both processes
# CMD ["/bin/bash"]
CMD ["/bin/bash", "-c", "\
  source /env/ubuntu_mcp_server/.venv/bin/activate && \
  python main.py && \
  wait"]