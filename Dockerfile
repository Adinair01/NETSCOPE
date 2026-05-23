# NetScope container image.
#
# Run with raw-socket privileges:
#     docker run --rm -it \
#         --cap-add=NET_RAW --cap-add=NET_ADMIN \
#         --network host \
#         -p 8080:8080 \
#         netscope --iface eth0
#
# --network host is the simplest way to capture real traffic; in production
# you would attach to a SPAN/mirror interface instead.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# libpcap is what Scapy hands raw packets off to on Linux.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 tcpdump \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY netscope ./netscope
COPY rules ./rules

EXPOSE 8080

ENTRYPOINT ["python", "-m", "netscope.main"]
CMD ["--rules", "rules/rules.yaml", "--host", "0.0.0.0"]
