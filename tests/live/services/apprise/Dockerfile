FROM python:3.13-alpine
COPY mock_apprise.py /service/mock_apprise.py
USER 65534:65534
ENTRYPOINT ["python", "/service/mock_apprise.py"]
