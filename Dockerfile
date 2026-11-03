FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

# Plain TCP connects only: no root or extra capabilities needed
USER 65534:65534
EXPOSE 8080
CMD ["python", "main.py"]
