import logging
import sys
from pythonjsonlogger import jsonlogger

"""
Logging Setup: 
- A log message is received. 
- It is then passed to a handler. 
- The handler decides where it goes. 
- A formatter decides how it looks. 
"""


def logging_setup():

    # Create handler to print logs to the console
    handler = logging.StreamHandler(sys.stdout)

    # Define a formatter to define what a log entry should look like
    # JSONFormatter ensures JSON is output instead of plain text
    formatter = jsonlogger.JsonFormatter(  # type: ignore
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    handler.setFormatter(formatter)

    # Get root logger
    logger = logging.getLogger()

    # Set log level
    logger.setLevel(logging.INFO)

    # Prevent duplicate logs
    logger.handlers.clear()

    # Add handler
    logger.addHandler(handler)
