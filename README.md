# License
*THIS SCRIPT IS PROVIDED TO YOU "AS IS." TO THE EXTENT PERMITTED BY LAW, QUALYS HEREBY DISCLAIMS ALL WARRANTIES AND LIABILITY FOR THE PROVISION OR USE OF THIS SCRIPT. IN NO EVENT SHALL THESE SCRIPTS BE DEEMED TO BE CLOUD SERVICES AS PROVIDED BY QUALYS*

# Summary 
This script is intended to pull a list of scanned images from the Qualys API. This will be a time range scoped data set based on the first specified epoch time. After the script completes, the max updated field is written to a config file so the next run of the script will start with the last specified max updated time stamp. The results of this script is the first level summary where there is vulnerability count columns for vulnerability severity counts for severities 1-5 as well as a column for each k:v pair returned in the json response to /csapi/v1.1/images endpoint.

# Prerequisites for running the script:
You must have Python3 installed.
Install pip for python3.
Run the following commands (Ubuntu):
sudo apt-get update
sudo apt-get install python3-pip

# Steps:
Use requirements.txt to install the required modules/packages.

## Script Requirements
This script is tested on Python 3.

This script requires the following PIP modules to run:
  requests, datetime, pyyaml

These modules can be installed with:
Linux
```
pip install -r requirements.txt
```
Windows
```
python3 -m pip install -r /path/to/requirements.txt
```
You may wish to use a [python virtual environment](https://docs.python.org/3/library/venv.html) as to not pollute your host system.


# Config Details:-
*Qualys API Username and Password*
Script is looking for environment variables for:
QUALYS_API_USERNAME={foo}
QUALYS_API_PASSWORD={bar}

*./config/config.conf*
updated = 1571077800000 (Modify updated date/Time in milli-seconds / linux epoch time, from when the image should get fetched)
batch_size= (Batch size could be from 1 to 1000)
scanned_only = 1(1 for scanned image, 0 for all images)
gateway_url = http://gateway.qg2.apps.qualys.com - (portal gateway api url, see CS API documentation for your Qualys API gateway URL - https://www.qualys.com/docs/qualys-container-security-api-guide.pdf - Authentication for gateway URLs)
csv = 1/0 (o to write output to console / 1 to write output to CSV in ./reports)

*./config/Last_Updated_Result*
File is created after initial run of script. This file stores the last updated max value for the previous script execution and subsequent runs of the script will use the previous executions maxUpdated value to pull images updated greater than this stored value. This value is updated after each execution pending the returned data set is not null.
To reset the script to begin from a new timestamp delete this file and set the value in ./config/config.conf to the new desired start timestamp.

# Run the script like :-
python3 FetchImages.py

python3 FetchImages.py "./someOtherDirectory/config.conf"

# Expected Output :-
Config.conf csv = 0/1
csv = 0
Image summary outputs to console.
csv = 1
Write image summery report to CSV in ./reports directory

# Logging
Logging configuration files is located in ./config/logging.yml. To change logging behavior, make changes in this file. For information on Python 3 logging visit https://docs.python.org/3/library/logging.html
Logging configuration
File Handler writes to log/FetchImages.log
Maximum Log size = 10 MB ( logging.yml line 18 - maxBytes: 10485760 # 10MB)
Backup file count = 5 (logging.yml line 19 - backupCount: 5)
Log Level = DEBUG ( Change to WARNING or higher for production - logging.yml line 15 - level: INFO)
