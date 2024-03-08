FROM busybox as trivy
WORKDIR /trivy
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.49.1/trivy_0.49.1_Linux-64bit.tar.gz -O- | tar -xz

FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY combinator.py .
COPY --from=trivy /trivy/trivy /usr/local/bin/trivy
ENTRYPOINT ["uvicorn",  "combinator:app",  "--host", "0.0.0.0"]
