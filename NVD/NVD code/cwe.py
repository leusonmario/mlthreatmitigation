import csv
import os
from asyncio import sleep

import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time

f = open('../../analysis/nvd-fixed-fixed-FINAL.csv', 'r')

data = csv.reader(f)
file_path = '../../analysis/cwefull-FINAL-fixed-FINAL.csv'
file_exists = os.path.isfile(file_path)

with open(file_path, 'a+', newline='') as g:  # Use 'newline=""' to prevent extra blank lines on Windows
    writer = csv.writer(g)

    if not file_exists or os.stat(file_path).st_size == 0:
        row = ['CWE_ID', 'CWE name', 'Availability', 'Confidentiality', 'Integrity', 'Access Control', 'Non-Repudiation', 'Other-Impact']
        writer.writerow(row)
g.close()

base_url = 'https://cwe.mitre.org/data/definitions/{endpoint}.html'
supported = 0
not_supported = 0

vul = set()
for row in data :
        if row[0] == 'CVE ID':#'Index':
            continue

        #cweName = row[0]
        cweName = row[2]
        availability = 0
        confidentiality = 0
        integrity = 0
        accessControl = 0
        nonRepudiation = 0
        other = 0

        options = webdriver.ChromeOptions()
        options.binary_location = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
        cwename = cweName[4:].lstrip('0')
        
        try:
            print(cwename)
            vul_number = int(cwename)
            if cwename in vul:
                supported += 1
            elif cwename not in vul:

                url = "https://cwe.mitre.org/data/definitions/" + cwename + ".html"
                response = requests.get(url)
                #time.sleep(2)

                if response.status_code == 200:
                    vul.add(cwename)
                    # soup = BeautifulSoup(driver.page_source, 'html.parser')
                    soup = BeautifulSoup(response.text, 'html.parser')
                    elem = soup.find("div", {"id": "Common_Consequences"})
                    #time.sleep(2)
                    if elem is not None:
                        # elem = elem.find("tbody")
                        table = elem.find('table', id='Detail')  # Find the table by its ID
                        scope_cell = table.find_all('td',
                                                    valign='middle')  # First <td> with "valign=middle" contains the Scope

                        # tl_div = elem.find_all('td', valign='middle')
                        for result in scope_cell:
                            #time.sleep(1)
                            if "Technical Impact" in result.text:
                                continue
                            if ("Availability" in result.text) and (availability == 0):
                                availability = 1
                            if ("Confidentiality" in result.text) and (confidentiality == 0):
                                confidentiality = 1
                            if ("Integrity" in result.text) and (integrity == 0):
                                integrity = 1
                            if ("Access Control" in result.text) and (accessControl == 0):
                                accessControl = 1
                            if ("Non-Repudiation" in result.text) and (nonRepudiation == 0):
                                nonRepudiation = 1
                            if ("Other" in result.text) and (other == 0):
                                other = 1


                        with open(file_path, 'a+',
                                  newline='') as g:  # Use 'newline=""' to prevent extra blank lines on Windows
                            writer = csv.writer(g)
                            writer.writerow(
                                [row[2], cwename, availability, confidentiality, integrity, accessControl, nonRepudiation,
                                 other])

                        g.close()
                else:
                    not_supported += 1
        except Exception as e:
            print(e)

print("Number of Overall Cases - Supported" + str(supported))
print("Number of Overall Cases - Not Supported" + str(not_supported))
