FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
# Install Python3, pip and OpenSSH server
RUN apt-get update && apt-get install -y \
    python3 python3-pip openssh-server sudo && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create SSH directory and set permissions
RUN mkdir /var/run/sshd

# Create a new user for SSH login
RUN useradd -m -s /bin/bash sandbox_ssh && \
    echo "sandbox_ssh:sandbox_password" | chpasswd && \
    # Allow password authentication for SSH user
    sed -i 's/^#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    # Permit user to use sudo without password (optional)
    echo "sandbox_ssh ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Optional: disable PAM to simplify (depends on your setup)
RUN sed -i 's/UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config

# Expose SSH port
EXPOSE 22

# Start sshd in the foreground
CMD ["/usr/sbin/sshd", "-D"]