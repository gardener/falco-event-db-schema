FROM python:3.14-alpine as builder

RUN apk update && \
    apk add gcc libpq-dev musl-dev

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt

FROM python:3.14-alpine

RUN apk update && \
    apk add libpq-dev

RUN mkdir -p /etc/code
COPY ./src/setup-database.py /etc/code/.

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
