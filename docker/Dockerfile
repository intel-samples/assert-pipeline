# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: MIT
FROM python:3.13

ARG UID=1000
ARG GID=1000

RUN apt-get update && apt-get install -y --no-install-recommends tmux ca-certificates ripgrep && rm -rf /var/lib/apt/lists/*

COPY src/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

RUN groupadd -g ${GID} runner && \
    useradd -u ${UID} -g ${GID} -m -s /bin/bash runner
