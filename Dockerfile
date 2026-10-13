FROM python:3.12-slim

# Install solc's runtime dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd --create-home --shell /bin/bash scanner

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir py-solc-x

# Copy source and install the package
COPY src ./src
RUN pip install --no-cache-dir -e .

# Copy fixtures for demo purposes
COPY tests ./tests

# Pre-install the default solc binary as the non-root user
USER scanner
RUN python -c "import solcx; solcx.install_solc('0.8.20'); solcx.install_solc('0.7.0')"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["solidity-guard"]
CMD ["--help"]

