FROM debian:oldstable-slim AS build

ARG DEBIAN_FRONTEND=noninteractive

# Install
COPY . /source
RUN sh /source/.github/install-dependencies.sh \
  /source/.github/build-dependencies.list \
  && rm -rf /var/lib/apt/lists/*
RUN cmake -DCMAKE_BUILD_TYPE=Release -DOPENVASD=0 -B/build /source \
  && DESTDIR=/install cmake --build /build -j$(nproc) -- install

FROM debian:oldstable-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN --mount=type=bind,source=.github,target=/source/ \
  sh /source/install-dependencies.sh \
  /source/runtime-dependencies.oldstable.list \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /install/ /

RUN ldconfig
