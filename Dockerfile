FROM python:3.8-slim-buster
WORKDIR /var/www
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP app/app.py
ENV FLASK_DEBUG false
ENV FLASK_RUN_HOST 0.0.0.0
ENV FLASK_RUN_PORT 5050
RUN apt-get update
RUN apt-get install gcc -y
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY app app
CMD ["python3", "-m", "flask", "--debug", "run"]
