FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn
COPY app.py email_privacy.py security.py ./
COPY templates/ templates/
COPY static/ static/
EXPOSE 5000
# Threads keep the app responsive while someone uploads or downloads a big Drive file.
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "8", "--timeout", "300"]
