FROM zalando/python:3.4.0-4

# needed for uwsgi_metrics (treap module)
RUN apt-get install m4 -q -y

COPY requirements.txt /
RUN pip3 install -r /requirements.txt

COPY app.py /
COPY scan.py /
COPY swagger.yaml /

WORKDIR /
CMD uwsgi --http :8080 -w app --master -p 16 --locks 9 --enable-metrics --mule
