FROM python:3

WORKDIR /home/app

ADD requirements.txt /home/app
RUN pip install --no-cache-dir --upgrade -r requirements.txt

ADD server.py /home/app
CMD ["uvicorn", "server:app", "--host", "0.0.0.0"]

EXPOSE 8000
