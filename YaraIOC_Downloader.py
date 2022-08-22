import requests, sys 
import pyfiglet
import pandas as pd
from colorama import init
from colorama import Fore, Back, Style
init()

import time 
import argparse
import os 
import concurrent.futures 
from datetime import datetime


class YaraIOC_Downloader:
    def __init__(self):
        self.api = "https://yaraify-api.abuse.ch/api/v1/" 

    def printer(self, log_text, log_type):
        """
        Will Write & Print Logs
        """
        datetime_text = datetime.now().strftime(f"{Fore.WHITE}[Date: %d-%m-%Y] [Time: %H:%M:%S]{Style.RESET_ALL} ")
        
        if log_type == "INFO":
            datetime_text += f'[{Fore.GREEN}{log_type}{Style.RESET_ALL}] '
            print(f'{datetime_text}{log_text}')
        elif log_type == 'ERROR':
            datetime_text += f'[{Fore.YELLOW}{log_type}{Style.RESET_ALL}] '
            print(f'{datetime_text}{log_text}')

    def get_arguments(self):
        banner = pyfiglet.figlet_format("Yara IOC Downloader")
        print(banner+"\n")
        parser = argparse.ArgumentParser(description=f'{Fore.RED}Yara Scanner v1.0')
        parser._optionals.title = f"{Fore.GREEN}Optional Arguments{Fore.YELLOW}"
        parser.add_argument("-s", "--single", dest="single_rule_name", help="Give Single Yara Rule Name",)
        parser.add_argument("-f", "--file", dest="file_containing_rule_name", help="File Containing Yara Rule Name, One Yara Rule Name in One Line.")    
        parser.add_argument("-t", "--timeout", dest="timeout", help="HTTP Request Timeout. default=60", default=60)
        parser.add_argument("-th", "--thread", dest="ThreadNumber", help="Parallel HTTP Request Number. default=100", default=100)
        
        required_arguments = parser.add_argument_group(f'{Fore.RED}Required Arguments{Fore.GREEN}')
        required_arguments.add_argument("-o", "--output", dest="output", help="Output file name.", required=True)
        return parser.parse_args()

    def start(self):
        arguments = self.get_arguments()

        # Fetching timeout & ThreadNumber 
        self.timeout      = arguments.timeout
        self.ThreadNumber = arguments.ThreadNumber

        # Formating Output file name 
        self.output_filename = arguments.output
        if self.output_filename.split('.')[-1] == 'csv':
            self.output_filename = self.output_filename + datetime.now().strftime('_%d-%m-%Y_%H_%M_%S') + ".csv"
        else:
            self.output_filename = self.output_filename.replace('.csv', '') + datetime.now().strftime('_%d-%m-%Y_%H_%M_%S') + ".csv"

        print("="*120)
        self.printer(f"{Fore.YELLOW}Initiating {Fore.GREEN}Yara IOC Downloader{Fore.YELLOW} ...{Style.RESET_ALL}", "INFO")
        print("="*120)

        # Checking what type of Input is given : Single Hash or Hash List
        if arguments.single_rule_name:
            rule_name = arguments.single_rule_name
            self.printer(f"{Fore.YELLOW}Fetching IOCs from Yara Rule Name: {Fore.GREEN}{rule_name}{Style.RESET_ALL}", "INFO")
            self.get_ioc(rule_name)
            self.export_to_excel()   

        elif arguments.file_containing_rule_name:
            file_containing_rule_name = arguments.file_containing_rule_name
            with open(file_containing_rule_name) as f:
                data_list = f.readlines()
            
            final_rule_name_list = set()
            for raw_yara_rule in data_list:
                if raw_yara_rule != "\n":
                    final_rule_name_list.add(raw_yara_rule.strip())

            self.total = len(final_rule_name_list)

            # Multi-Threaded Implementation
            # executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.ThreadNumber)
            # futures = [executor.submit(self.get_ioc, hash) for hash in final_rule_name_list]
            # concurrent.futures.wait(futures) 

            total = len(final_rule_name_list)
            progress = 0
            for rule_name in final_rule_name_list:
                progress += 1
                self.printer(f"[Progress: {progress}/{total}] {Fore.YELLOW}Fetching IOCs from Yara Rule Name: {Fore.GREEN}{rule_name}{Style.RESET_ALL}", "INFO")
                self.get_ioc(rule_name)
                time.sleep(1.5)
            self.export_to_excel()   
            
        else:
            print(f"{Fore.RED}[!] Please Provide either {Fore.YELLOW}File Containing list{Fore.RED} or {Fore.YELLOW}Single Yara Rule Name{Fore.RED}, {Fore.GREEN}type {sys.argv[0]} --help for more.{Style.RESET_ALL}")
            sys.exit() 

    def get_ioc(self, yara_rule):
        # curl -X POST -d '{ "query": "lookup_hash", "search_term": "MALWARE_Win_Neshta" '} https://yaraify-api.abuse.ch/api/v1/ 
        try:
            post_data = {
                "query": "get_yara", 
                "search_term": str(yara_rule),
                "result_max": 1000,
            }

            response = requests.post(self.api, json=post_data, timeout=self.timeout)
            data = response.json()
            data_list = []
            for raw_data in data["data"]:
                # IOC Hashes
                md5    = raw_data["md5_hash"]
                sha1   = raw_data["sha1_hash"]
                sha256 = raw_data["sha256_hash"]

                for hash, hash_type in {md5:"MD5", sha1:"SHA1", sha256:"SHA256"}.items():
                    data_list.append({
                        "Threat Actor Name": yara_rule,
                        "IOC Value": hash,
                        "IOC Type": hash_type
                    })
            
            df = pd.DataFrame(data_list)    
            self.write_data_to_csv(self.output_filename, df)
        except Exception as e: 
            print("Error: ", e) 

    def write_data_to_csv(self, filename, df):
        with open(filename, 'a', encoding='utf-8') as f:
            df.to_csv(f, header=f.tell() == 0, encoding='utf-8', index=False, line_terminator='\n') 

    def export_to_excel(self):
        df = pd.read_csv(self.output_filename)

        print("="*120)
        self.printer(f"{Fore.YELLOW}Removing {Fore.GREEN}Duplicates{Fore.YELLOW} ...{Style.RESET_ALL}", "INFO")
        df = df.drop_duplicates(subset='IOC Value', keep='first')

        # Removing Any Row whose Value is CSV Header
        df = df.drop(df[df['Threat Actor Name'] == 'Threat Actor Name'].index)
        df = df.drop(df[df['IOC Value']   == 'IOC Value'].index)
        df = df.drop(df[df['IOC Type']    == 'IOC Type'].index) 

        writer = pd.ExcelWriter(self.output_filename.replace(".csv", ".xlsx"), engine = 'xlsxwriter')
        workbook  = writer.book        
        # Add a header format.
        header_format = workbook.add_format({
            'bold': True,
            'font_size': 10,
            'fg_color': '#7bb8ed',
            'border': 1}
        )   

        df.to_excel(writer, sheet_name='Yara_Report', index=False, encoding='utf-8')
        worksheet1 = writer.sheets['Yara_Report']

        for col_num, value in enumerate(df.columns.values):
            worksheet1.write(0, col_num, value, header_format)
            column_len = df[value].astype(str).str.len().max()
            column_len = max(column_len, len(value)) + 3
            worksheet1.set_column(col_num, col_num, column_len)

        writer.save()    
        self.printer(f"{Fore.GREEN}Done!{Style.RESET_ALL}", "INFO")
        print("="*120)
        os.remove(self.output_filename)

if __name__ == "__main__":
    test = YaraIOC_Downloader()
    test.start()