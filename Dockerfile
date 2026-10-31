# ===================================================================
# ForensiQ — Digital Forensic Investigation Toolkit
# Production Dockerfile for Railway Deployment
# ===================================================================

# Stage 1: Build the Rust backend binary
FROM rust:1.82-slim-bookworm AS builder

WORKDIR /usr/src/forensiq

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy backend manifests to cache dependencies
COPY backend/Cargo.toml ./
COPY backend/Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release || true
RUN rm -rf src

# Copy real backend source code and migrations
COPY backend/src ./src
COPY backend/migrations ./migrations

# Build the release binary
RUN touch src/main.rs && cargo build --release

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled binary from builder
COPY --from=builder /usr/src/forensiq/target/release/backend /app/forensiq-backend

# Copy static frontend assets and demo files
COPY static /app/static
COPY ForensiQ_Project_Abstract.pdf /app/ForensiQ_Project_Abstract.pdf

# Create runtime directories
RUN mkdir -p /app/carved_output /app/evidence_vault

# Configure runtime environment
ENV PORT=3000
ENV FORENSIQ_EVIDENCE_ROOT=/app/evidence_vault
ENV CARVED_OUTPUT_DIR=/app/carved_output

EXPOSE 3000

CMD ["/app/forensiq-backend"]

