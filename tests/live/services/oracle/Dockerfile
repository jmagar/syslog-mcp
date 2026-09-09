FROM python:3.13-alpine@sha256:540c7d91f98ff6880174c40e99067bf5941eb54d818a7a5e094d188b196a934d
WORKDIR /app
COPY oracle.py /app/oracle.py
COPY redirect.py /app/redirect.py
COPY producer.py /app/producer.py
RUN mkdir -p /capture && chmod 0777 /capture
USER 65534:65534
ENTRYPOINT ["python", "/app/oracle.py"]
