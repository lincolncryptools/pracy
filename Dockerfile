# syntax=docker/dockerfile:1
# Based on:
# - https://github.com/DoreenRiepel/FABEO/blob/master/Dockerfile
# - https://github.com/JHUISI/charm/blob/dev/Dockerfile
# - https://docs.docker.com/reference/dockerfile/

# Use specific Ubuntu 22.04 version
FROM ubuntu:jammy-20250404

# Setup environment
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Disable interactive prompts for some installations
RUN echo "debconf debconf/frontend select Noninteractive" | debconf-set-selections

# Install essential packages
RUN apt update && apt upgrade -y
RUN apt install -y locales wget gcc flex bison build-essential m4 git lsb-release cmake
RUN apt install -y libssl-dev libgmp-dev
RUN apt install -y libreadline6-dev zlib1g-dev libncurses-dev
RUN apt install -y libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev python-tk python3-tk tk-dev

# Setup different versions of Python
RUN apt install -y python3 python3-dev python3-setuptools python3-pip
RUN apt install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa
# For Charm + backend
RUN apt install -y python3.9 python3.9-dev python3.9-venv python3.9-distutils python3.9-lib2to3 python3.9-gdbm python3.9-tk
# For pracy compiler + utility scripts
RUN apt install -y python3.13 python3.13-dev python3.13-venv python3.13-gdbm python3.13-tk
RUN pip3 install py pytest pyparsing setuptools numpy

# Avoid running everything as root
RUN apt install -y sudo
RUN groupadd -g 999 pracy
RUN useradd --create-home --uid 999 --gid 999 --groups sudo --shell /bin/bash pracy
RUN sed -i /etc/sudoers -re 's/^%sudo.*/%sudo ALL=(ALL:ALL) NOPASSWD: ALL/g'
RUN sed -i /etc/sudoers -re 's/^root.*/root ALL=(ALL:ALL) NOPASSWD: ALL/g'
RUN sed -i /etc/sudoers -re 's/^#includedir.*/## **Removed the include directive** ##"/g'
USER pracy
WORKDIR /home/pracy

# Install GMP 5.1.3 (for Charm)
WORKDIR /home/pracy
RUN mkdir -p /home/pracy/libs/gmp-5.1.3
RUN wget https://ftp.gnu.org/gnu/gmp/gmp-5.1.3.tar.gz
RUN tar -xf gmp-5.1.3.tar.gz
WORKDIR /home/pracy/gmp-5.1.3
RUN ./configure --prefix=/home/pracy/libs/gmp-5.1.3 --exec-prefix=/home/pracy/libs/gmp-5.1.3
RUN make
RUN make install
WORKDIR /home/pracy
RUN rm gmp-5.1.3.tar.gz
RUN rm -r gmp-5.1.3

# Install PBC 0.5.14 (for Charm)
WORKDIR /home/pracy
RUN mkdir -p /home/pracy/libs/pbc-0.5.14
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
RUN tar -xf pbc-0.5.14.tar.gz
WORKDIR /home/pracy/pbc-0.5.14
RUN env CPPFLAGS="-I/home/pracy/libs/gmp-5.1.3/include/" LDFLAGS="-L/home/pracy/libs/gmp-5.1.3/lib/" \
    ./configure --prefix=/home/pracy/libs/pbc-0.5.14 --exec-prefix=/home/pracy/libs/pbc-0.5.14
RUN make
RUN make install
WORKDIR /home/pracy
RUN rm pbc-0.5.14.tar.gz
RUN rm -r pbc-0.5.14

# Install Charm 0.50
WORKDIR /home/pracy
RUN mkdir -p /home/pracy/libs/charm-0.50
RUN git clone https://github.com/JHUISI/charm ./charm-0.50
WORKDIR /home/pracy/charm-0.50
RUN git checkout 13e1928
# Install for Python 3.9.22 (installed by deadsnakes)
# Note: for some reason --prefix is ignored during install?
RUN ./configure.sh \
    --prefix=/home/pracy/libs/charm-0.50 \
    --python=/usr/bin/python3.9 \
    --extra-cflags="-I/home/pracy/libs/gmp-5.1.3/include -I/home/pracy/libs/pbc-0.5.14/include" \
    --extra-ldflags="-L/home/pracy/libs/gmp-5.1.3/lib -L/home/pracy/libs/pbc-0.5.14/lib"
RUN make
RUN sudo make install
RUN sudo ldconfig
WORKDIR /home/pracy
RUN sudo rm -r ./charm-0.50

# Install Relic 0.5.0
WORKDIR /home/pracy
RUN mkdir -p /home/pracy/libs/relic-0.5.0
RUN git clone https://github.com/relic-toolkit/relic.git ./relic-0.5.0
WORKDIR /home/pracy/relic-0.5.0
RUN git checkout 260c9f8b
RUN mkdir relic_target
RUN sed -i "s/-DSHLIB=OFF/-DSHLIB=ON/g" ./preset/x64-pbc-bls12-381.sh
WORKDIR /home/pracy/relic-0.5.0/relic_target
RUN ../preset/x64-pbc-bls12-381.sh ../
RUN make
RUN env DESTDIR="/home/pracy/libs/relic-0.5.0" make install
WORKDIR /home/pracy
RUN rm -r ./relic-0.5.0

# Pull in schemes
COPY --chown=pracy:pracy ./schemes /home/pracy/schemes

# Pull in all code for compiler
COPY --chown=pracy:pracy ./src /home/pracy/compiler/src
COPY --chown=pracy:pracy ./tests /home/pracy/compiler/tests
COPY --chown=pracy:pracy ./pyproject.toml ./requirements.txt ./README.md /home/pracy/compiler/

# Setup virtual env for compiler
RUN mkdir -p /home/pracy/venvs
WORKDIR /home/pracy/venvs
RUN python3.13 -m venv --prompt "compiler" ./compiler
RUN /home/pracy/venvs/compiler/bin/pip install -r /home/pracy/compiler/requirements.txt
RUN /home/pracy/venvs/compiler/bin/pip install --editable /home/pracy/compiler

# Pull in backends
COPY --chown=pracy:pracy ./backends/charm /home/pracy/backends/charm
COPY --chown=pracy:pracy ./backends/relic /home/pracy/backends/relic
RUN mkdir -p /home/pracy/backends/relic/_build

# Pull in utility scripts
COPY --chown=pracy:pracy ./tools/test_relic_backend.py /home/pracy/scripts/
COPY --chown=pracy:pracy --chmod=774 ./commands/* /home/pracy/commands/

# Place user in correct folder
WORKDIR /home/pracy
