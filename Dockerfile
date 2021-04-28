# daemon runs in the background
# run something like tail /var/log/Talleod/current to see the status
# be sure to run with volumes, ie:
# docker run -v $(pwd)/Talleod:/var/lib/Talleod -v $(pwd)/wallet:/home/Talleo --rm -ti Talleo:0.2.2
ARG base_image_version=0.10.0
FROM phusion/baseimage:$base_image_version

ADD https://github.com/just-containers/s6-overlay/releases/download/v1.21.2.2/s6-overlay-amd64.tar.gz /tmp/
RUN tar xzf /tmp/s6-overlay-amd64.tar.gz -C /

ADD https://github.com/just-containers/socklog-overlay/releases/download/v2.1.0-0/socklog-overlay-amd64.tar.gz /tmp/
RUN tar xzf /tmp/socklog-overlay-amd64.tar.gz -C /

ARG TALLEO_VERSION=v0.4.7.1105
ENV TALLEO_VERSION=${TALLEO_VERSION}

# install build dependencies
# checkout the latest tag
# build and install
RUN apt-get update && \
    apt-get install -y \
      build-essential \
      python-dev \
      gcc-4.9 \
      g++-4.9 \
      git cmake \
      libboost1.58-all-dev \
      librocksdb-dev && \
    git clone https://github.com/TalleoProject/Talleo /src/Talleo && \
    cd /src/Talleo && \
    git checkout $TALLEO_VERSION && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_CXX_FLAGS="-g0 -Os -fPIC -std=gnu++11" .. && \
    make -j$(nproc) && \
    mkdir -p /usr/local/bin && \
    cp src/Talleod /usr/local/bin/Talleod && \
    cp src/walletd /usr/local/bin/walletd && \
    cp src/simplewallet /usr/local/bin/simplewallet && \
    cp src/miner /usr/local/bin/miner && \
    strip /usr/local/bin/Talleod && \
    strip /usr/local/bin/walletd && \
    strip /usr/local/bin/simplewallet && \
    strip /usr/local/bin/miner && \
    cd / && \
    rm -rf /src/Talleo && \
    apt-get remove -y build-essential python-dev gcc-4.9 g++-4.9 git cmake libboost1.58-all-dev librocksdb-dev && \
    apt-get autoremove -y && \
    apt-get install -y  \
      libboost-system1.58.0 \
      libboost-filesystem1.58.0 \
      libboost-thread1.58.0 \
      libboost-date-time1.58.0 \
      libboost-chrono1.58.0 \
      libboost-regex1.58.0 \
      libboost-serialization1.58.0 \
      libboost-program-options1.58.0 \
      libicu55

# setup the Talleod service
RUN useradd -r -s /usr/sbin/nologin -m -d /var/lib/Talleod Talleod && \
    useradd -s /bin/bash -m -d /home/Talleo Talleo && \
    mkdir -p /etc/services.d/Talleod/log && \
    mkdir -p /var/log/Talleod && \
    echo "#!/usr/bin/execlineb" > /etc/services.d/Talleod/run && \
    echo "fdmove -c 2 1" >> /etc/services.d/Talleod/run && \
    echo "cd /var/lib/Talleod" >> /etc/services.d/Talleod/run && \
    echo "export HOME /var/lib/Talleod" >> /etc/services.d/Talleod/run && \
    echo "s6-setuidgid Talleod /usr/local/bin/Talleod" >> /etc/services.d/Talleod/run && \
    chmod +x /etc/services.d/Talleod/run && \
    chown nobody:nogroup /var/log/Talleod && \
    echo "#!/usr/bin/execlineb" > /etc/services.d/Talleod/log/run && \
    echo "s6-setuidgid nobody" >> /etc/services.d/Talleod/log/run && \
    echo "s6-log -bp -- n20 s1000000 /var/log/Talleod" >> /etc/services.d/Talleod/log/run && \
    chmod +x /etc/services.d/Talleod/log/run && \
    echo "/var/lib/Talleod true Talleod 0644 0755" > /etc/fix-attrs.d/Talleod-home && \
    echo "/home/Talleo true Talleo 0644 0755" > /etc/fix-attrs.d/Talleo-home && \
    echo "/var/log/Talleo true nobody 0644 0755" > /etc/fix-attrs.d/Talleod-logs

VOLUME ["/var/lib/Talleod", "/home/Talleo","/var/log/Talleod"]

ENTRYPOINT ["/init"]
CMD ["/usr/bin/execlineb", "-P", "-c", "emptyenv cd /home/Talleo export HOME /home/Talleo s6-setuidgid Talleo /bin/bash"]
