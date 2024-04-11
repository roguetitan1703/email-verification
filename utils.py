def parse_log():

    with open('logs/script_logs.log','r') as file:
        array = file.readlines()
        
    rcpt = []

    defer = ["5.1.1", "5.7.1", "RCPT TO command result: 550, b'No such user'", 'RCPT TO command result: 250','RCPT TO command result: 550, b"5.1.1 The email account that you tried to reach does not exist.']
    for line in array:
        flag = False
        if 'RCPT TO command result' not in line:
            continue
        for _ in defer:
            if _ in line:
                flag = True
                
        if not flag:
            rcpt.append(line)
            
            

    with open('rcpt.log','w+') as file:
        file.writelines(rcpt)        
    

def update_files():
    valid_domains_file = "data/valid_domains.txt"
    catchall_domains_file = "data/catchall_domains.txt"
    not_catchall_domains_file = "data/not_catchall_domains.txt"
    verified_emails_file = "data/verified_emails.txt"
    csv_file = "emails_validated.csv"
    
    header = ['email','is_valid','has_mx_record','is_disposable','is_catchall','is_deliverable']
    
    index = {
        'email': 0,
        'is_valid': 1,
        'has_mx_record': 2,
        'is_disposable': 3,
        'is_catchall':4,
        'is_deliverable':5
    }
    
    records = []
    with open(csv_file, 'r') as file:
        array = file.readlines()
        
        for line in array:
            line = line.replace("\n",'')
            records.append(line.split(','))

    # print(records)        
    
    # for valid domains
    with open(valid_domains_file, 'r') as file:
        valid_domains_ = file.readlines()
        valid_domains = []
        
        for line in valid_domains:
            line = line.replace("\n",'')
            valid_domains.append(line)
            
    # for catchall domains
    with open(catchall_domains_file, 'r') as file:
        catchall_domains_ = file.readlines()
        catchall_domains = []

        for line in catchall_domains:
            line = line.replace("\n", '')
            catchall_domains.append(line)
            
    # for not catchall domains
    with open(not_catchall_domains_file, 'r') as file:
        not_catchall_domains_ = file.readlines()
        not_catchall_domains = []

        for line in not_catchall_domains:
            line = line.replace("\n", '')
            not_catchall_domains.append(line)
            
    # for verified emails
    with open(verified_emails_file, 'r') as file:
        verified_emails_ = file.readlines()
        verified_emails = []

        for line in verified_emails:
            line = line.replace("\n", '')
            verified_emails.append(line)
            
            
    # Adding new records
    for record in records:
        if record[index['has_mx_record']] == 'True':
            domain = record[index['email']].split('@')[1]
            if domain in valid_domains:
                continue
            
            print(f'Added {domain} to valid domains')
            valid_domains.append(domain)

        if record[index['is_catchall']] == 'True':
            domain = record[index['email']].split('@')[1]
            if domain in catchall_domains:
                continue
            print(f'Added {domain} to catchall domains')
            catchall_domains.append(domain)
            
        if record[index['is_catchall']] == 'False':
            domain = record[index['email']].split('@')[1]
            if domain in not_catchall_domains:
                continue
            print(f'Added {domain} to not catchall domains')
            not_catchall_domains.append(domain)

        if record[index['is_deliverable']] == 'True':
            email = record[index['email']]
            if email in verified_emails:
                continue
            print(f'Added {email} to verified emails')
            verified_emails.append(email)  
    
    
    # Adding records
    with open(valid_domains_file, 'w') as file:
        file.writelines(_ + "\n" for _ in valid_domains)
        
    with open(catchall_domains_file, 'w') as file:
        file.writelines(_ + "\n" for _ in catchall_domains)
        
    with open(not_catchall_domains_file, 'w') as file:
        file.writelines(_ + "\n" for _ in not_catchall_domains)
        
    with open(verified_emails_file, 'w') as file:
        file.writelines(_ + "\n" for _ in verified_emails)
        
if __name__ == "__main__":
    update_files()