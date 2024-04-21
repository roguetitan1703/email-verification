from validate_email.regex_check import regex_check
from validate_email.email_address import EmailAddress
from validate_email.exceptions import AddressFormatError
import csv
import random, string
import dns.resolver
from disposable_email_domains import blocklist
import smtplib
from time import sleep
from piapy import PiaVpn
from ultra_logger import Logger
import os

mailer = {
    # "host": "smtp.office365.com",
    "port": 25
}

credentials = {
    "email": "your mail",
    "password": "your password"
}

class EmailValidator:
    """
    Class for validating and analyzing email addresses.
    """

    def __init__(self, email, reroute=False, debug=False, logger=None):
        """
        Initializes the validator with an email address.
        Connects to a VPN location

        Args:
            email (str): The email address to be validated.

        Raises:
            ValueError: If the provided email address is empty.
        """
        
        # Create the "logs" directory if it doesn't exist
        logs_dir = 'logs'
        if not os.path.exists(logs_dir):
            print(f'Creating the "logs" directory')
            os.makedirs(logs_dir)
            
        # Create data folder if it doesn't exist
        data_folder = "data"
        if not os.path.exists(data_folder):
            os.makedirs(data_folder)

        # Create text files with full paths
        self.valid_domains_file = os.path.join(data_folder, "valid_domains.txt")
        self.catchall_domains_file = os.path.join(data_folder, "catchall_domains.txt")
        self.not_catchall_domains_file = os.path.join(data_folder, "not_catchall_domains.txt")
        self.verified_emails_file = os.path.join(data_folder, "verified_emails.txt")

        # Optionally check and create the text files (if needed)
        self._create_text_files()
    
        if not logger:
            self.logging = Logger(f'Script_logs', 'logs/script_logs.log', log_to_console=True)
        else:
            self.logging = logger
                    
        if not email:
            raise ValueError("Email address cannot be empty")
        
        try:
            self.email = email
            self.email_object = EmailAddress(email)
            self.domain = self.email_object.domain
            self.user = self.email_object.user
            self.ace = self.email_object.ace
            self.ace_domain = self.email_object.ace_domain
            self.domain_literal_ip = self.email_object.domain_literal_ip
        
        except AddressFormatError:
            raise ValueError("Invalid email address")

        if reroute:
            try:
                self.vpn = PiaVpn()
                self.vpn_regions = self.vpn.regions()
                
                if self.vpn.status() == "Connected":
                    self.logging.info("VPN Already Connected")
                    self.vpn.disconnect()
                    self.logging.info("VPN Disconnected")
                    sleep(1)
                    
                self.region = random.choice(self.vpn_regions)
                self.logging.info(f'Attempting to connect at {self.region}')
                self.vpn.connect(self.region)
                sleep(1)                
            except Exception as e:
                self.logging.exception(f'Unexpected error:{e}',exc_info=True)     
                
        self.debug = 1 if debug else 0     
        self.mx_records = None      

    def _create_text_files(self):
        """
        Creates the text files if they don't already exist.
        """
        for filename in [self.valid_domains_file, self.catchall_domains_file, self.verified_emails_file, self.not_catchall_domains_file]:
            if not os.path.exists(filename):
                with open(filename, "w") as f:
                    pass
                
    def _check_with_local_file(self, filename, entity):
        """
        Checks if the email address or domain is in the database.

        Args:
            filename (str): The name of the local file to check.

        Returns:
            bool: True if the entity is in the file, False otherwise.
        """
        with open(filename, "r") as f:
            return entity in f.read().splitlines()
        

    def _add_to_local_file(self, filename, entity):
        """
        Adds the email address or domain to the local file.

        Args:
            filename (str): The name of the local file to add the entity to.
            entity (str): The email address or domain to add.
        """
        with open(filename, "a") as f:
            f.write(entity + "\n")
            
    def is_valid_syntax(self) -> bool:
        """
        Checks if the email address adheres to basic structural formatting using regular expressions.

        Returns:
            bool: True if the email address has valid syntax, False otherwise.
        """

        try:
            self.logging.info(f'Checking email syntax for {self.email}')
            success  = regex_check(self.email_object)
            self.logging.info(f'Email syntax check result: {success}')
            return success
        except AddressFormatError:
            self.logging.exception(f'Invalid email address: {self.email}')            
            return False

    def has_mx_record(self) -> bool:
        """
        Checks if the email domain has a valid MX record indicating it can receive emails.

        Returns:
            bool: True if the domain has a valid MX record, False otherwise (including errors during lookup).
        """

        # Check locally first
        is_local = False
        if self._check_with_local_file(self.valid_domains_file, self.domain):
            self.logging.info(f'{self.domain} is in valid domains file')
            is_local = True
            return True
        
        try:
            self.logging.info(f'Checking MX record for {self.domain}')
            success, mx_records = EmailUtils.get_mx_record(self.domain)
            self.mx_records = mx_records[0] if success else None
            self.logging.info(f'MX record check result: {success}, MX records:{mx_records}')
            
            if not is_local and success:
                self._add_to_local_file(self.valid_domains_file, self.domain)
                self.logging.info(f'Added {self.domain} to valid domains file')
            return success
        
        except Exception as e:
            self.logging.exception(f'Unexpected error:{e}', exc_info=True)
            return False

    def get_mx(self) -> str:
        """
        Returns the MX record for the email domain.

        Returns:
            str: The MX record for the email domain.
        """
        if self.mx_records is None:
            return EmailUtils.get_mx_record(self.domain)[1][0]
        else:
            return self.mx_records
    
    def is_disposable(self) -> bool:
        """
        Checks if the email address belongs to a disposable email provider domain.

        Returns:
            bool: True if the email address uses a disposable email domain, False otherwise.
        """

        try:
            self.logging.info(f'Checking disposable email domain for {self.domain}')
            success = self.domain in blocklist
            self.logging.info(f'Disposable email domain check result: {success}')
            return success
        except Exception as e:
            self.logging.exception(f'Unexpected error:{e}', exc_info=True)
            return False
            
    def is_catchall(self, port=25, timeout=10):
        """
        Checks if a domain is catchall using the RCPT TO command.

        Args:
            email_address (str): The email address to check.
            port (int, optional): The port to use for the SMTP connection. Defaults to 25.
            timeout (int, optional): The timeout value in seconds for the connection attempt. Defaults to 10.

        Returns:
            bool: True if the server accepts the recipient email address, False otherwise.
            str: A descriptive error message if the check fails.
        """

        # Check locally first
        is_local = False
        if self._check_with_local_file(self.catchall_domains_file, self.domain):
            self.logging.info(f'{self.domain} is in catchall domains file')
            is_local = True
            return True
        
        elif self._check_with_local_file(self.not_catchall_domains_file, self.domain):
            self.logging.info(f'{self.domain} is in not catchall domains file')
            is_local = True
            return False
            
        try:
            self.logging.info(f'Checking catchall for {self.domain}')
            # Connect to the SMTP server
            host = self.get_mx()
            self.logging.info(f'Attempting to connect at {host} with port:{port}')
            with smtplib.SMTP(host, port) as smtp:
                smtp.set_debuglevel(self.debug)
                self.logging.info(f'Setting SMTP debug level: {self.debug}')
                self.logging.info(f'Echoing the server: {smtp.ehlo()}')
                # self.logging.info(f'Starting TLS connection: {smtp.starttls()}')
                # self.logging.info(f'Echoing the server: {smtp.ehlo()}')

                self.logging.info(f'Simulating sender address: {smtp.mail(credentials["email"])}')
                
                random_email = EmailUtils.generate_random_email(self.domain)
                self.logging.info(f'Simulating recipient address: {random_email}')
                code, message = smtp.rcpt(random_email)
                self.logging.info(f'RCPT TO command result: {code}, {message}')
                
                if code == 451:
                    return code
                
                if not is_local and code == 250:
                    self._add_to_local_file(self.catchall_domains_file, self.domain)
                    self.logging.info(f'Added {self.domain} to catchall domains file')
                    
                if not is_local and code != 250:
                    self._add_to_local_file(self.not_catchall_domains_file, self.domain)
                    self.logging.info(f'Added {self.domain} to not catchall domains file')
                                    
                    
                return code == 250

        except (smtplib.SMTPAuthenticationError, smtplib.SMTPSenderRefused) as e:
            # Group authentication and sender rejection errors (related to sender)
            self.logging.exception(f'Authentication Error: {e}', exc_info=True)
            return False

        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPDataError) as e:
            # Group recipient rejection and data transfer errors (related to recipient)
            self.logging.exception(f'Recipient Error: {e}', exc_info=True)
            return False

        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected,
                smtplib.SMTPHeloError, smtplib.SMTPNotSupportedError, OSError) as e:
            # Group low-level connection and protocol errors
            self.logging.exception(f'Connection Error: {e}', exc_info=True)
            return False

        except Exception as e:
            # Catch other unforeseen issues
            self.logging.exception(f'Unexpected Error: {e}', exc_info=True)
            return False
        
        
    def is_deliverable(self, port=25, timeout=10):
        """
        Checks if an email address is likely deliverable using the RCPT TO command.

        Args:
            email_address (str): The email address to check.
            port (int, optional): The port to use for the SMTP connection. Defaults to 25.
            timeout (int, optional): The timeout value in seconds for the connection attempt. Defaults to 10.

        Returns:
            bool: True if the server accepts the recipient email address, False otherwise.
            str: A descriptive error message if the check fails.
        """

        # Check locally first
        is_local = False
        if self._check_with_local_file(self.verified_emails_file, self.email):
            self.logging.info(f'{self.email} is in verified emails file')
            is_local = True
            return True
        
        try:
            self.logging.info(f'Checking deliverability for {self.domain}')
            # Connect to the SMTP server
            host = self.get_mx()
            self.logging.info(f'Attempting to connect at {host} with port:{port}')
            with smtplib.SMTP(host, port) as smtp:
                smtp.set_debuglevel(self.debug)
                self.logging.info(f'Setting SMTP debug level: {self.debug}')
                self.logging.info(f'Echoing the server: {smtp.ehlo()}')
                # self.logging.info(f'Starting TLS connection: {smtp.starttls()}')

                self.logging.info(f'Simulating sender address: {smtp.mail(credentials["email"])}')
                
                code, message = smtp.rcpt(self.email)
                self.logging.info(f'RCPT TO command result: {code}, {message}')
                
                if code == 451:
                    return code
                
                if not is_local and code == 250:
                    self._add_to_local_file(self.verified_emails_file, self.email)
                    self.logging.info(f'Added {self.email} to verified emails file')
                    
                return code == 250

        except (smtplib.SMTPAuthenticationError, smtplib.SMTPSenderRefused) as e:
            # Group authentication and sender rejection errors (related to sender)
            self.logging.exception(f'Authentication Error: {e}', exc_info=True)
            return False

        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPDataError) as e:
            # Group recipient rejection and data transfer errors (related to recipient)
            self.logging.exception(f'Recipient Error: {e}', exc_info=True)
            return False

        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected,
                smtplib.SMTPHeloError, smtplib.SMTPNotSupportedError, OSError) as e:
            # Group low-level connection and protocol errors
            self.logging.exception(f'Connection Error: {e}', exc_info=True)
            return False

        except Exception as e:
            # Catch other unforeseen issues
            self.logging.exception(f'Unexpected Error: {e}', exc_info=True)
            return False
        
              
    def check_email(self):
        """
        Checks all the aspect of the email address by checking its syntax, MX record, Disposable domain, catchall status and if the email exists (is deliverable).

        Returns:
            dict: A dictionary containing the results.
        """

        results = {
            "email": self.email,
            "is_valid_syntax": self.is_valid_syntax(),
            "has_mx_record": self.has_mx_record(),
            "is_disposable": self.is_disposable(),
            "is_catchall": self.is_catchall(),
            "is_deliverable": self.is_deliverable()
        }

        return results
    
    def validate(self):
        """
        Validates the email address by checking its syntax, MX record, Disposable domain, catchall status and if the email exists (is deliverable).

        Returns:
            dict: containing the validation results.
        """
        score = 0.0
        
        is_valid = self.is_valid_syntax()
        if is_valid:
            
            has_mx_record = self.has_mx_record() 
            is_disposable = self.is_disposable()
            
            if has_mx_record:
                is_catchall = self.is_catchall()
                if is_catchall:
                    is_deliverable = None
                else:
                    is_deliverable = self.is_deliverable() 
            else:
                is_catchall,is_deliverable = None,None
        
        else:
            has_mx_record,is_disposable,is_catchall,is_deliverable = None,None,None,None
            
            
        if is_catchall or is_catchall == 451:
            score += -3    
        else:
            score += 2
        score += -3 if is_disposable else 2
        score = score + 2 if is_valid else 0 
        score = score + 1 if has_mx_record else 0
        if is_deliverable is not None and is_deliverable != 451:
            if is_deliverable:
                score += 3
            else:
                score = 0

        return {
            'email':self.email,
            'is_valid':is_valid,
            'has_mx_record':has_mx_record,
            'is_disposable':is_disposable,
            'is_catchall':is_catchall,
            'is_deliverable':is_deliverable,
            'quality_score': score
        }
        

class EmailUtils:
    """Utility class for email-related tasks."""

    @staticmethod
    def read_from_text_file(file_path):
        """
        Reads all comma-separated domain names from a text file.

        Args:
            file_path (str): The path to the text file containing domain names.

        Returns:
            list[str]: A list of domain names stripped of whitespace.
        """

        with open(file_path, 'r') as file:
            file_content = file.read()
            return [element.strip() for element in file_content.split(",")]

    @staticmethod
    def write_array_dict_to_csv(file_path, results):
        """
        Writes an array dictionary to a CSV file with keys as header row.

        Args:
            file_path (str): The path to the CSV file for writing the results.
            results (list[dict]): A list of dictionaries containing email-related data.
        """

        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)

            header = list(results[0].keys())  # Assuming all dictionaries have the same keys
            writer.writerow(header)

            for row in results:
                values = [str(row[key]) for key in header]
                writer.writerow(values)
    
    @staticmethod            
    def write_dict_to_csv(file_path, dict):
        """
        Writes a dictionary to a CSV file.

        Args:
            file_path (str): The path to the CSV file for writing the results.
            results (dict): A ]dictionary containing email-related data.
        """

        with open(file_path, 'a', newline='') as file:
            writer = csv.writer(file)
            header = list(dict.keys())  
            # writer.writerow(header)
            values = list(dict.values())
            writer.writerow(values)
    
    @staticmethod        
    def write_header_to_csv(file_path, dict):
        """
        Writes a header row to a CSV file.

        Args:
            file_path (str): The path to the CSV file for writing the header.
            header (dict): A dictionary who's keys will be the list of header strings.
        """

        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)
            header = list(dict.keys())
            writer.writerow(header)

    @staticmethod
    def get_mx_records_bulk(domains):
        """
        Retrieves MX records for multiple domains in bulk.

        Args:
            domains (list[str]): A list of domain names to query for MX records.

        Returns:
            list[dict]: A list of dictionaries containing domain information and MX records (or error messages).
        """

        results = []
        for domain in domains:
            success, mx_records = EmailValidator.get_mx_record(domain)
            result = {
                'domain': domain,
                'is_mx_found': success,
                'mx_records': mx_records
            }
            results.append(result)
        return results
    
    @staticmethod
    def get_mx_record(domain):
        """
        Retrieves MX records for a single domain.

        This function remains the same as the original implementation.

        Args:
            domain (str): The domain name to query for MX records.

        Returns:
            tuple(bool, list[str]): A tuple containing a boolean indicating success and a list of MX records or error messages.
        """

        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return True, [str(mx_record.exchange) for mx_record in mx_records]
        except dns.resolver.NXDOMAIN:
            return False, ["Domain not found"]
        except dns.resolver.NoAnswer:
            return False, ["No MX records found"]
        except dns.resolver.Timeout:
            return False, ["Timeout error"]
        except dns.resolver.YXDOMAIN:
            return False, ["Domain should not exist"]
        except dns.resolver.NoNameservers:
            return False, ["No name servers found"]
        except Exception as e:
            return False, ["Error: " + str(e)]
        
    @staticmethod
    def generate_random_email(domain):
        """
        Generate a random valid syntax email address.

        Args:
            domain (str): The domain name for the email address.

        Returns:
            str: A randomly generated email address.
        """
        username_length = 10
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=username_length)) + 'falan'  # Random username

        return f"{username}@{domain}"


    @staticmethod
    def test():
        """
        Test funtion to check all the functions of the EmailValidator
        """
        emails = ['user.name@gmail.com','omchandel1703@gmail.com','demon23om47@gmail.com']
        for email in emails:
            validator = EmailValidator(email)
            print('-----Email Parts-----')
            print(f'Email {validator.email}')
            print(f'Email object {validator.email_object}')
            print(f'Domain {validator.domain}')
            print(f'Random email: {EmailUtils.generate_random_email(validator.domain)}')
            print(f'User {validator.user}')
            print(f'ACE {validator.ace}')
            print(f'ACE domain {validator.ace_domain}')
            print(f'Domain literal IP {validator.domain_literal_ip}')
            print('-----Email Validation-----')
            print(f'1. Validate syntax: {validator.is_valid_syntax()}')
            print(f'2. Has MX record: {validator.has_mx_record()}')
            print(f'3. Is disposable: {validator.is_disposable()}')
            print(f'MX records: {EmailUtils.get_mx_record(validator.domain)}')


if __name__ == "__main__":
    validator = EmailValidator('alan@watersavergardens.com.au')
    print(validator.validate())
    