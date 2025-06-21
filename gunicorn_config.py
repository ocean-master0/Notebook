# Gunicorn Configuration for Secure Notebook Application

import multiprocessing
import os

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "gthread"
worker_connections = 1000
threads = 2

# Request handling
max_requests = 1000
max_requests_jitter = 100
timeout = 30
keepalive = 2

# Application
preload_app = True
reload = False

# Logging
accesslog = "-"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'
errorlog = "-"
loglevel = "info"
capture_output = True

# Process naming
proc_name = "secure_notebook"

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Performance
worker_tmp_dir = "/dev/shm"
enable_stdio_inheritance = True

# SSL Configuration (uncomment and configure for HTTPS)
# keyfile = "/path/to/your/private.key"
# certfile = "/path/to/your/certificate.crt"
# ssl_version = 3
# ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"

# Development settings (set to False in production)
if os.getenv('FLASK_ENV') == 'development':
    reload = True
    workers = 1
    loglevel = "debug"

def when_ready(server):
    """Called just after the server is started."""
    server.log.info("Secure Notebook server is ready. Listening on %s", server.address)

def worker_int(worker):
    """Called just after a worker has been killed."""
    worker.log.info("Worker %s received INT or QUIT signal", worker.pid)

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info("Worker spawned successfully (pid: %s)", worker.pid)

def post_worker_init(worker):
    """Called just after a worker has initialized the application."""
    worker.log.info("Worker initialized (pid: %s)", worker.pid)

def worker_abort(worker):
    """Called when a worker receives the SIGABRT signal."""
    worker.log.info("Worker aborted (pid: %s)", worker.pid)
