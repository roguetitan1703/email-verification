from email_validate import EmailValidator, EmailUtils
import os
from logger import Logger
import csv

continuation = True
emails = EmailUtils.read_from_text_file("emails.txt")
data = []
header = False if not continuation else True
csv_file = 'emails_validated.csv'
logs_dir = 'logs'
if not os.path.exists(logs_dir):
    print(f'Creating the "logs" directory')
    os.makedirs(logs_dir)

logging = Logger(f'Script_logs', 'logs/script_logs.log', log_to_console=True)

schedule = []

with open(csv_file, 'r') as f:
    data = csv.reader(f)
    existing_data = list(data)

existing_data = [x[0] for x in existing_data]

for email in emails:
    
    if email in existing_data:
        print(f'email already exists in database {email}')
        continue
    try:
        mail = EmailValidator(email,logger=logging)
        results = mail.validate()
        
        if results['is_catchall'] == 451 or results['is_deliverable'] == 451:
            schedule.append(email)
            continue
        
        print(results)
        
        if not header:
            EmailUtils.write_header_to_csv(csv_file, results)
            header = True
            
        # data.append(results)
        EmailUtils.write_dict_to_csv(csv_file, results)
        
    except Exception as e:
        print(f'email not valid {email}')
          
          
# Second batch
for email in schedule:
    try:
        mail = EmailValidator(email, logger=logging)
        results = mail.validate()

        if results['is_catchall'] == 451:
            results['is_catchall'] = None
            
        if results['is_deliverable'] == 451:
            results['is_deliverable'] = None

        print(results)

        if not header:
            EmailUtils.write_header_to_csv(csv_file, results)
            header = True

        # data.append(results)
        EmailUtils.write_dict_to_csv(csv_file, results)

    except Exception as e:
        print(f'email not valid {email}')
          
          

    
    
    
