# Use the official Rust image from the Docker Hub
FROM rust:1.77 as builder

#RUN apt-get update && apt-get install -y \
#    build-essential \
#    cmake \
#    pkg-config \
#    libclang-dev \
#    openssl \
#    libgmp-dev \
#    && rm -rf /var/lib/apt/lists/*

# Set the environment variable to suppress all compiler warnings
ENV RUSTFLAGS="-A warnings"

WORKDIR rvss_artifact
COPY . .

RUN cargo build --release

# Default command runs the benchmarks without displaying warnings
CMD ["cargo", "bench", "--bench", "rvss", "--quiet"]

# docker build -t rvss_app .
# docker run --rm rvss_app
