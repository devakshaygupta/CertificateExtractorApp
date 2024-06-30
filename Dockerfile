# syntax=docker/dockerfile:1

FROM ubuntu:oracular

# Set environment variables to avoid user prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages: curl, apt, git, and dependencies for .NET SDK, runtime, OpenJDK 17, and Maven
RUN apt-get update && \
    apt-get install -y curl apt-transport-https gnupg ca-certificates && \
    apt-get install -y git && \
    # Add Microsoft's GPG key
    curl -sSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | tee /usr/share/keyrings/microsoft.gpg > /dev/null && \
    # Add the Microsoft package repository
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/24.04/prod noble main" | tee /etc/apt/sources.list.d/microsoft.list && \
    # Update package lists
    apt-get update && \
    # Install .NET SDK and runtime
    apt-get install -y dotnet-sdk-8.0 dotnet-runtime-8.0 && \
    # Install OpenJDK 17
    apt-get install -y openjdk-21-jdk && \
    # Install Maven
    apt-get install -y maven && \
    # Clean up
    apt-get clean && rm -rf /var/lib/apt/lists/*
