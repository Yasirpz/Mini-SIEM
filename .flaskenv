FLASK_APP=app:create_app

# Debug mode is OFF by default, and that is a security decision rather than a
# preference. Werkzeug's debugger turns an unhandled exception into an
# interactive Python console in the browser, and prints source and local
# variables into the traceback. On a machine that is collecting Windows
# Security logs and holding an administrator session, that is not a debugger,
# it is a remote shell waiting for a stack trace.
#
# Turn it on deliberately while developing -- it also gives you auto-reload,
# so template and code edits appear without restarting Flask:
#
#     set FLASK_DEBUG=1 && flask run          (Windows, cmd)
#     $env:FLASK_DEBUG=1; flask run           (Windows, PowerShell)
#     FLASK_DEBUG=1 flask run                 (Linux/macOS)
#
# Never with the server reachable from anything but localhost.
FLASK_DEBUG=0
