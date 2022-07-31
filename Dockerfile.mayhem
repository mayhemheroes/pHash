FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake libpng-dev libjpeg-dev libtiff-dev libavcodec-dev libavformat-dev libsamplerate0-dev libswscale-dev libsndfile-dev

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DPHASH_EXAMPLES=1 -DWITH_AUDIO_HASH=1 -DWITH_VIDEO_HASH=1 -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpng-dev libsndfile-dev libsamplerate0-dev libavcodec-dev libavformat-dev libswscale-dev
COPY --from=builder /install /install
ENV LD_LIBRARY_PATH=/install/lib
