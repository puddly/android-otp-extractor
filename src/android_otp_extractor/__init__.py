import logging

TRACE = logging.DEBUG - 5
logging.addLevelName(TRACE, 'TRACE')


class TraceLogger(logging.getLoggerClass()):
    def trace(self, msg, *args, **kwargs):
        self.log(TRACE, msg, *args, **kwargs)


logging.setLoggerClass(TraceLogger)

logger = logging.getLogger(__name__)  # so the project has a root logger
