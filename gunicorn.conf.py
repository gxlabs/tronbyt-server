from gunicorn.workers import base

# python3 -m gunicorn --config gunicorn.conf.py "tronbyt_server:create_app()"

bind = "0.0.0.0:8000"
loglevel = "debug"
accesslog = "-"
access_log_format = "%(h)s %(l)s %(u)s %(t)s %(r)s %(s)s %(b)s %(f)s %(a)s"
errorlog = "-"
workers = 5
threads = 4
timeout = 120
reload = False
preload_app = True
capture_output = True


# https://github.com/benoitc/gunicorn/issues/1391
def post_worker_init(worker: base.Worker) -> None:
    import atexit
    import importlib

    _exit_function = getattr(
        importlib.import_module("multiprocessing.util"), "_exit_function", None
    )
    if _exit_function:
        atexit.unregister(_exit_function)
    worker.log.info("worker post_worker_init done, (pid: {})".format(worker.pid))
