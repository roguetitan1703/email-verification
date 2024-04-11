import logging, colorlog, functools

class Logger:
    def __init__(self, log_name, log_file, log_to_console=True, clear_previous=False,):
        # Name of the logger to differentiate later
        self.log_name = log_name
        # The log file where the log statements are to be saved
        self.log_file = log_file
        # Whether to log to console or not (only needed when debugging through console)
        self.log_to_console = log_to_console
        # Whether to log in debug mode or not
        self.clear_previous = clear_previous
        
        # Initialising the logger
        self.logger = colorlog.getLogger(self.log_name)
        # Setting the logger to the lowest level DEBUG-> INFO-> WARNING-> ERROR -> CRITICAL, a logger only logs statements which are on or above it's level
        self.logger.setLevel(logging.DEBUG)
        # Managing all the handlers
        self.handlers = {}        
        # Setting up a custom color formatter for better visuals of the log and easy readability
        self.console_formatter = colorlog.ColoredFormatter(
            '%(asctime)s - %(log_color)s%(levelname)-8s%(reset)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        )
        
        self.file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s- %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )
        
        # Setting up the loggers handlers
        self.setup_handlers()
        
        
    # Function to setup the file handler which will log to the specified log file 
    def setup_file_handler(self):
        file_handler = logging.FileHandler(self.log_file)
        # Set the level to DEBUG to allow all the logs
        file_handler.setLevel(logging.DEBUG)
        # Add the handler to the handlers dictionary
        self.handlers['file_handler'] = file_handler

        # Add the file handler to the logger
        self.logger.addHandler(file_handler)
        
        # Set the formatter to the color_formatter for the file handler
        file_handler.setFormatter(self.file_formatter)
    
    
    # Function to setup the console handler which will log to the console, and will be usef for immediate feedback during development
    def setup_console_handler(self):
        console_handler = logging.StreamHandler()
        # Set the level to CRITICAL if log_to_console if False making the console_logger to only log statements to console if they are CRITICAL
        console_handler.setLevel(logging.CRITICAL if not self.log_to_console else logging.DEBUG)
        # Add the handler to the handlers dictionary
        self.handlers['console_handler'] = console_handler
        
        # Add the console_handler to the logger
        self.logger.addHandler(console_handler)
        
        # Set the formatter to the color_formatter for the console handler
        console_handler.setFormatter(self.console_formatter)
        

    # Setup all the handlers at once
    def setup_handlers(self):
        self.setup_file_handler()
        self.setup_console_handler() 

        # If clear_previous is set to be true, the log file is cleared before writing new logs
        if self.clear_previous:
            self.clear_log_file()
            # self.log_message('info', 'Starting Program')
        
        
    # Enable console logging if it was disabled previously
    def enable_console_logging(self):
        self.log_to_console = True
        if self.handlers['console_handler'] in self.logger.handlers:
            # Check for the console handler and set its level to DEBUG to allow all logs to log through console 
            self.handlers['console_handler'].setLevel(logging.DEBUG)    
    
    
    # Disable console logging if it was enabled previously or default
    def disable_console_logging(self):
        self.log_to_console = False
        if self.handlers['console_handler'] in self.logger.handlers:
            # Check for the console handler and set its level to CRITICAL to only log to console if they are CRITICAL
            self.handlers['console_handler'].setLevel(logging.CRITICAL)
            
            
    # Remove a handler from the logger permanently
    def remove_handler(self, handler):
        # Deleting the handler from the handlers dictionary
        del self.handlers[handler]
        # Check if the handler is present in the logger's handlers
        for handler_ in self.logger.handlers:
            if handler_ == handler:
                # Remove the handler from the logger permanently
                self.logger.removeHandler(handler_)
                break
            
            
    # Custom log message function which logs the message through all the handlers, It then depends on the handler's level if the log message will pass through
    def log_message(self, log_level, message):
        # Validate the log level provided by the user
        log_level = log_level.upper()
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ValueError("Invalid log level. Expected one of: DEBUG, INFO, WARNING, ERROR, CRITICAL")

        # Mapping log levels to corresponding logging methods
        log_level_mapping = {
            'DEBUG': self.logger.debug,
            'INFO': self.logger.info,
            'WARNING': self.logger.warning,
            'ERROR': self.logger.error,
            'CRITICAL': self.logger.critical
        }

        # Log the message with the specified log level using the mapped logging method
        log_level_mapping[log_level](message)
        
    # Default logging, a way to expose the base logging functions
    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)
        
    def warning(self, message):
        self.logger.warning(message)
        
    def error(self, message):
        self.logger.error(message)
        
    def critical(self, message):
        self.logger.critical(message)

    def exception(self, message, exc_info=None):
        self.logger.exception(message, exc_info=exc_info)

    def log_session(self,func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            self.log_message('info', '---------- Log session started ----------')
            result = func(*args, **kwargs)
            self.log_message('info', '---------- Log session ended ---------')
            return result
        return wrapper
    

    # Read and display the contents of the log file line by line
    def read_log_file(self):
        with open(self.log_file, 'r') as file:
            for line in file:
                line = line.strip()  # To remove any leading/trailing whitespace
                print(line)


    # Clear log file in case of unwanted log statements filling up the log file
    def clear_log_file(self):
        with open(self.log_file, 'w') as file:
            # Opening the file in 'w' mode truncates it, effectively clearing its contents.
            pass


if __name__ == '__main__':
    logger = Logger('test', 'test.log')
    logger.log_message('info','Testing log_message: ')
    logger.log_message('info', 'This is a test message')
    logger.log_message('warning', 'This is a warning message')
    logger.log_message('error', 'This is an error message')
    logger.log_message('critical', 'This is a critical message')


    logger.log_message('info', 'Testing default loggers: ')
    logger.info("This is a test message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")
    logger.exception("This is an exception message")