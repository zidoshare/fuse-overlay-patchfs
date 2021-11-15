# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.205.2/containers/ubuntu/.devcontainer/base.Dockerfile

# [Choice] Ubuntu version (use hirsuite or bionic on local arm64/Apple Silicon): hirsute, focal, bionic
FROM ubuntu:focal
RUN sed -i s/archive.ubuntu.com/mirrors.aliyun.com/g /etc/apt/sources.list\
    && sed -i s/security.ubuntu.com/mirrors.aliyun.com/g /etc/apt/sources.list\
    && apt-get update\
    && apt-get install --no-install-recommends -y gcc libleveldb-dev libc6-dev g++ make automake autoconf clang pkgconf libfuse3-dev

# [Optional] Uncomment this section to install additional OS packages.
# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
#     && apt-get -y install --no-install-recommends <your-package-list-here>


