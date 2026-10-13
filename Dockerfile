FROM python:3.12-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends cmake build-essential git && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/vital-q
COPY requirements*.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN bash src/release/build_native.sh /opt/oqs-build
ENV OQS_INSTALL_PATH=/opt/oqs-build/install PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
ENTRYPOINT ["python", "scripts/reproduce.py"]
CMD ["replay", "--output", "/outputs/replay"]
