uwsgi -s 127.0.0.1:8808 -w AccessLogFilter:app -d /var/log/uwsgi.log
