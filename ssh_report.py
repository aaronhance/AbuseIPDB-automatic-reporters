import re, csv, json, requests, os, datetime

# INFO
# 
# Made by Aaron Hance https://github.com/aaronhance/AbuseIPSB-automatic-reporters
# This is a Python3 script for bulk reporting SSH brute force attempts.
#
# Use the following command to manually get failed SSH logins, or uncomment the automatic log grabbing below.
# grep sshd.\*Failed /var/log/auth.log > log.txt 
#

# CONFIGURATION
input_log_name = "log.txt" # Leave at default if using automatic log grabbing.
output_report_name = "reports.csv" # Will be overwritten everytime the script is run.
api_key = "" # Place your AbuseIPDB APIv2 key here.
api_endpoint = "https://api.abuseipdb.com/api/v2/bulk-report"
# END CONFIGURATION

# Uncomment for auto grabbing and rotating of auth log file
#os.system('grep sshd.\\*Failed /var/log/auth.log > log.txt')
#os.system('cp /var/log/auth.log \"/var/log/auth.' + str(datetime.datetime.now()) + '.log\"')
#os.system('> /var/log/auth.log')

api_header = {'Accept': 'application/json', 'Key': api_key}
responses = []
total_reports = 0

fails = open(input_log_name, "r")
lines = fails.readlines()

header = ["IP","Categories","ReportDate","Comment"]
catagories = "18,22"
for i in range(int( len(lines) / 9999 ) + 1):
    reports = []
    for line in lines[int(i * 9999):int(i * 9999) + 9999]:
        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)[0]
        date = line[:15]
        comment = "SSH Brute Force, " + line[16:len(line)-1]
        reports.append([ip, catagories, date, comment])

    with open(str(i) + output_report_name, mode='w', newline='') as cfile:
        writer = csv.writer(cfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(header)

        for report in reports:
            writer.writerow(report)

    responses.append(requests.post(api_endpoint, headers=api_header, files={'csv': open(str(i) + output_report_name, mode='r')} ))
    try:
        total_reports += int(responses[i].json()['data']['savedReports'])
    except:
        print(responses[i])
        print(responses[i].json()['errors'][0]['detail'])

print(str(total_reports) + " IPs reported, good job! :)")
