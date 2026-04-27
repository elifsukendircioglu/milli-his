FROM python:3.11-slim

# nmap'i sisteme kur
RUN apt-get update && apt-get install -y nmap && apt-get clean

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# data klasörünü oluştur
RUN mkdir -p data/reports

# CVE seed'i başlangıçta çalıştır
RUN python database.py || true

EXPOSE 8000

CMD ["sh", "-c", "python database.py && python cve_seed.py && uvicorn main:app --host 0.0.0.0 --port 8000"]