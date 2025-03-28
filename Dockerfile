FROM python:3.12.6

RUN useradd -m atri

RUN mkdir /atri-reports
WORKDIR /atri-reports
COPY . /atri-reports

RUN chown -R atri:atri /atri-reports
USER atri
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python3", "main.py"]