FROM registry.opensource.zalan.do/stups/python:3.5.0-7

# needed for uwsgi_metrics (treap module)
RUN apt-get install m4 -q -y

COPY requirements.txt /
RUN pip3 install -r /requirements.txt
RUN chmod +x /usr/local/bin/uwsgi

COPY app.py /
COPY scan.py /
COPY swagger.yaml /
COPY scm-source.json /

WORKDIR /
CMD uwsgi --http :8080 -w app --master -p 16 --locks 9 --enable-metrics --mule \
    --logformat 'INFO:uwsgi.request: %(addr) "%(method) %(uri) %(proto)" %(status) %(size) "%(uagent)"'
