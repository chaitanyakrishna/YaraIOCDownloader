# YaraIOCDownloader
This script will download IOCs based on the rule name defined in Yara rules and leverages abuse.ch API service to fetch the IOCs
# Usage

```
$python YaraIOC_Downloader.py -h
__   __                ___ ___   ____
\ \ / /_ _ _ __ __ _  |_ _/ _ \ / ___|
 \ V / _` | '__/ _` |  | | | | | |
  | | (_| | | | (_| |  | | |_| | |___
  |_|\__,_|_|  \__,_| |___\___/ \____|

 ____                      _                 _
|  _ \  _____      ___ __ | | ___   __ _  __| | ___ _ __
| | | |/ _ \ \ /\ / / '_ \| |/ _ \ / _` |/ _` |/ _ \ '__|
| |_| | (_) \ V  V /| | | | | (_) | (_| | (_| |  __/ |
|____/ \___/ \_/\_/ |_| |_|_|\___/ \__,_|\__,_|\___|_|



usage: YaraIOC_Downloader.py [-h] [-s SINGLE_RULE_NAME]
                             [-f FILE_CONTAINING_RULE_NAME] [-t TIMEOUT]
                             [-th THREADNUMBER] -o OUTPUT

Yara Scanner v1.0

Optional Arguments:
  -h, --help            show this help message and exit
  
  -s SINGLE_RULE_NAME, --single SINGLE_RULE_NAME
                        Give Single Yara Rule Name
  -f FILE_CONTAINING_RULE_NAME, --file FILE_CONTAINING_RULE_NAME
                        File Containing Yara Rule Name, One Yara Rule Name in
                        One Line.
  -t TIMEOUT, --timeout TIMEOUT 
                        HTTP Request Timeout. default=60
  -th THREADNUMBER, --thread THREADNUMBER 
                        Parallel HTTP Request Number. default=100

Required Arguments:

  -o OUTPUT, --output OUTPUT Output file name.
  ```
  
  # Single Rulename
  
  ```
$python YaraIOC_Downloader.py -s LockbitBlack_Loader -o LockbitBlack_Loader
__   __                ___ ___   ____
\ \ / /_ _ _ __ __ _  |_ _/ _ \ / ___|
 \ V / _` | '__/ _` |  | | | | | |
  | | (_| | | | (_| |  | | |_| | |___
  |_|\__,_|_|  \__,_| |___\___/ \____|

 ____                      _                 _
|  _ \  _____      ___ __ | | ___   __ _  __| | ___ _ __
| | | |/ _ \ \ /\ / / '_ \| |/ _ \ / _` |/ _` |/ _ \ '__|
| |_| | (_) \ V  V /| | | | | (_) | (_| | (_| |  __/ |
|____/ \___/ \_/\_/ |_| |_|_|\___/ \__,_|\__,_|\___|_|



========================================================================================================================
[Date: 22-08-2022] [Time: 13:22:06] [INFO] Initiating Yara IOC Downloader ...
========================================================================================================================
[Date: 22-08-2022] [Time: 13:22:06] [INFO] Fetching IOCs from Yara Rule Name: LockbitBlack_Loader
========================================================================================================================
[Date: 22-08-2022] [Time: 13:22:08] [INFO] Removing Duplicates ...
[Date: 22-08-2022] [Time: 13:22:09] [INFO] Done!
========================================================================================================================


  ```
# Fetch IOCs from rule name containing from a file
  ```
$type rule.txt
Guloader_VBScript
LATAMHotel_Obfuscated_BAT
lnk_from_chinese
loader_win_bumblebee

$YaraIOC Downloader>python YaraIOC_Downloader.py -f rule.txt -o yararules-iocs
__   __                ___ ___   ____
\ \ / /_ _ _ __ __ _  |_ _/ _ \ / ___|
 \ V / _` | '__/ _` |  | | | | | |
  | | (_| | | | (_| |  | | |_| | |___
  |_|\__,_|_|  \__,_| |___\___/ \____|

 ____                      _                 _
|  _ \  _____      ___ __ | | ___   __ _  __| | ___ _ __
| | | |/ _ \ \ /\ / / '_ \| |/ _ \ / _` |/ _` |/ _ \ '__|
| |_| | (_) \ V  V /| | | | | (_) | (_| | (_| |  __/ |
|____/ \___/ \_/\_/ |_| |_|_|\___/ \__,_|\__,_|\___|_|



========================================================================================================================
[Date: 22-08-2022] [Time: 13:23:50] [INFO] Initiating Yara IOC Downloader ...
========================================================================================================================
[Date: 22-08-2022] [Time: 13:23:50] [INFO] [Progress: 1/4] Fetching IOCs from Yara Rule Name: Guloader_VBScript
[Date: 22-08-2022] [Time: 13:23:55] [INFO] [Progress: 2/4] Fetching IOCs from Yara Rule Name: loader_win_bumblebee
[Date: 22-08-2022] [Time: 13:23:59] [INFO] [Progress: 3/4] Fetching IOCs from Yara Rule Name: LATAMHotel_Obfuscated_BAT
[Date: 22-08-2022] [Time: 13:24:02] [INFO] [Progress: 4/4] Fetching IOCs from Yara Rule Name: lnk_from_chinese
Error:  'data'
========================================================================================================================
[Date: 22-08-2022] [Time: 13:24:05] [INFO] Removing Duplicates ...
[Date: 22-08-2022] [Time: 13:24:05] [INFO] Done!
========================================================================================================================
  ```
