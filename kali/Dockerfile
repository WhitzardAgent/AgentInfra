# Kali Linux latest with useful tools by tsumarios
FROM kalilinux/kali-rolling

# Set working directory to /app
WORKDIR /app

# Update
RUN apt -y update && DEBIAN_FRONTEND=noninteractive apt -y dist-upgrade && apt -y autoremove && apt clean

# Install common and useful tools
RUN apt -y install curl wget vim git net-tools whois netcat-traditional pciutils usbutils bzip2

# Install useful languages (install python3-pip to get some Python tools before conda setup if needed)
RUN apt -y install golang nodejs npm

# Install Kali Linux "Top 10" metapackage and cybersecurity useful tools
RUN DEBIAN_FRONTEND=noninteractive apt -y install kali-tools-top10 exploitdb man-db dirb nikto wpscan uniscan lsof apktool dex2jar ltrace strace binwalk

# Install Miniconda
# ENV CONDA_DIR=/opt/conda
# ENV PATH=$CONDA_DIR/bin:$PATH

# RUN wget --quiet https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O /tmp/miniconda.sh && \
#     bash /tmp/miniconda.sh -b -p $CONDA_DIR && \
#     rm /tmp/miniconda.sh && \
#     $CONDA_DIR/bin/conda clean -tipsy

# Create conda environment with python 3.11 (modify python version if you want)
# Install virtualenv (or you can just use python3 -m venv)
RUN apt -y update && \
    DEBIAN_FRONTEND=noninteractive apt -y dist-upgrade && \
    apt -y autoremove && apt clean && \
    apt -y install python3 python3-pip python3-virtualenv

# Create a virtualenv in /opt/venv
RUN python3 -m virtualenv /opt/venv

# Activate virtualenv by default
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"


# Activate conda environment by default
# SHELL ["conda", "run", "-n", "myenv", "/bin/bash", "-c"]

# Clone the repo (so it's ready inside the container)
COPY MCP-Kali-Server-main /app/kali_mcp

RUN chmod +x /app/kali_mcp/start.sh

RUN pip install flask fastmcp

# Expose port as before
EXPOSE 5001

# Default command: start bash with conda environment activated
CMD ["/bin/bash"]