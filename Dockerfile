FROM python:3

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

RUN apt-get update && apt-get -y dist-upgrade
RUN apt-get -y install build-essential libssl-dev libffi-dev libblas3 libc6 liblapack3 gcc python3-dev python3-pip cython3
RUN apt-get -y install python3-numpy python3-scipy 
RUN apt install -y netcat

RUN pip install --upgrade pip

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY manage.py uwsgi.py entrypoint.sh /

RUN chmod +x entrypoint.sh

COPY authz .

ENTRYPOINT ["/code/entrypoint.sh"]

CMD ["uwsgi", "uwsgi.ini"]

