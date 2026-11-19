# Builds the EMS server into a small image.
#   docker build -f deploy/Dockerfile -t ems-server .
#   docker run -d --name ems -p 127.0.0.1:2021:2021 -v ems-data:/data ems-server
#   docker logs ems        # the first start prints the admin password

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p ems-server

FROM debian:bookworm-slim
RUN useradd --system --home /data --shell /usr/sbin/nologin ems && install -d -o ems -g ems /data
COPY --from=build /src/target/release/ems-server /usr/local/bin/ems-server
USER ems
ENV EMS_BIND=0.0.0.0:2021 EMS_DATA_DIR=/data EMS_TRUST_PROXY=1
VOLUME /data
EXPOSE 2021
ENTRYPOINT ["/usr/local/bin/ems-server"]
