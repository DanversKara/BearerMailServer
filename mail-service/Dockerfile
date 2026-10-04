FROM python:3.11-slim

WORKDIR /app

# DejaVu fonts: saving an email as PDF keeps accents and non-Latin letters
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py bearer_ext.py calendar_ext.py ddns_ext.py dmarc_ext.py drive_ext.py invites_ext.py mail_auth.py relay_ext.py security_ext.py tabs_ext.py users_ext.py ./

# SMTP=25, API=8080
EXPOSE 25 465 587 8080

CMD ["python", "app.py"]
