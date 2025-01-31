import json
import csv
from requests.auth import HTTPBasicAuth
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

def readFileaAndWrite(file, readers, writer, valid_cwe = []) :
    l = open(file)
    data2 = json.load(l)

    for i in range(0, len(data2['CVE_Items'])) :
        
        # CPE dependency name and version
        dep = data2['CVE_Items'][i]['configurations']['nodes']
        if(len(dep)> 0) : 
            dep = dep[0]['cpe_match']
            if(len(dep)> 0) : 
                dep = dep[0]['cpe23Uri']
                # CVE severity
            cve = ""
            metric = ""

            try:
                severity = 'N/A'
                cve = data2['CVE_Items'][i]['cve']['CVE_data_meta']['ID']
                metric = data2['CVE_Items'][i]['impact']['baseMetricV3']
                if metric:
                    severity = str(metric['cvssV3']['baseSeverity']).lower()
                else:
                    metric = data2['CVE_Items'][i]['impact']['baseMetricV2']
                    if metric:
                        severity = str(metric['severity']).lower()
            except KeyError as e:
                print(e)

            availability = 0
            confidentiality = 0
            integrity = 0
            accessControl = 0
            nonRepudiation = 0
            other = 0


            # CWE name
            if cve != "" and metric != "":
                cwe = data2['CVE_Items'][i]['cve']['problemtype']['problemtype_data'][0]['description']
                if(len(cwe) > 0) :
                    cwe = cwe[0]['value']
                    description = data2['CVE_Items'][i]['cve']['description']['description_data'][0]['value']

                    #related Attacks
                    relatedAttacks = []
                    if ("XSS" in description) or ("cross-site" in description) or "arbitrary sites" in description: relatedAttacks.append("Stored Cross-Site Scripting (XSS) attack")
                    if ("heap overflow" in description): relatedAttacks.append(
                        "Heap-based Buffer Overflow")
                    if ("memory leak" in description) or ("memory corruption" in description): relatedAttacks.append(
                        "Resource Management")
                    if ("lack input validation" in description) or "validate the input" in description: relatedAttacks.append(
                        "Improper Input Validation")
                    if ("information disclosure" in str(description).lower()) or ("timing attack" in str(description).lower()) \
                            or "sensitive information" in str(description).lower(): relatedAttacks.append(
                        "Information disclosure attack")
                    if ("prototype pollution" in str(description).lower()): relatedAttacks.append(
                        "Prototype Pollution attack")
                    if (("DoS" in description) or ("denial" in description) or ("buffer overflow" in str(description).lower()) or
                            ("slow down a ws server") in description) or "improperly initializes" in description or "buffer over-read" in description\
                            or "erroneous function" in description or "to crash due to" in description\
                            or "would crash" in description or "stack overflow" in description:
                        relatedAttacks.append("Denial of Service (DoS)")
                        availability = 1
                    if ("RCE" in description) or ("remote" in description) :
                        relatedAttacks.append("Remote code execution (RCE) attack")
                    if "CSRF" in description : relatedAttacks.append("Cross-site request forgery (CSRF) attack")
                    if "after free" in str(description).lower(): relatedAttacks.append("Use-after-free attack")
                    if (("bypass" in description) or ("wrong client certificate" in description)
                            or ("prohibited reuse" in description) or "reusing wrong connections" in description
                            or "wrongly accepts percent-encoded" in description):
                        relatedAttacks.append("Bypass authentication attack")
                    if "SQL" in description : relatedAttacks.append("SQL injection attack")
                    if "privilege" in description or "users to escape" in description:
                        relatedAttacks.append("Privilege escalation attack")
                        confidentiality = 1
                        integrity = 1
                        accessControl = 1
                    if "RPC" in description : relatedAttacks.append(" RPC attack ")
                    if ("authoriz" in description) or ("authentica" in description):
                        confidentiality = 1
                        accessControl = 1
                    if ("sensitive" in description) :
                        integrity = 1
                    if ("XML" in description):
                        relatedAttacks.append(" XML Injection attack ")
                        confidentiality = 1
                        integrity = 1
                    if (("NULL" in description) or "binding a reference to null" in str(description).lower()
                            or "bind references to null" in description):
                        relatedAttacks.append(" NULL pointer dereference attack ")
                        confidentiality = 1
                        integrity = 1
                    if ("modif" in description) or ("inject" in description):
                        confidentiality = 1
                        accessControl = 1
                    if ("integrity" in description) : integrity = 1
                    if ("confidentiality" in description) : confidentiality = 1
                    if ("availability" in description) : availability = 1
                    if ("access control" in description) : accessControl = 1
                    if ("non repudiation" in description) : nonRepudiation = 1
                    if ("arbitrary code" in description) or ("execute arbitrary" in description) or " command string to be executed" in description \
                            or ("execute command" in description) or "code injection" in description\
                            or "verification code is lenient" in description:
                        relatedAttacks.append("Arbitrary code attack ")
                        confidentiality = 1
                        integrity = 1
                    if "vulnerability" in description[8:120] :
                        if(len(relatedAttacks)==0) :
                            relatedAttacks.append(description.partition("vulnerability")[0] + " attack")


                if(len(cwe) < 10) :
                    for row2 in readers :
                        if(row2[0]== cwe[4:8]) :
                            availability = int(row2[1])
                            confidentiality = int(row2[2])
                            integrity = int(row2[3])
                            accessControl = int(row2[4])
                            nonRepudiation = int(row2[5])
                            other = int(row2[6])
                #Categories Path
                categoriesPath = []
                if (availability == 1) : categoriesPath.append("Availability")
                if(confidentiality == 1) : categoriesPath.append("Confidentiality")
                if(integrity == 1) : categoriesPath.append("Integrity")
                if(accessControl == 1) : categoriesPath.append("Access Control")
                if(nonRepudiation == 1) : categoriesPath.append("Non-Repudiation")
                if(other == 1) : categoriesPath.append("Other")
                categoriesPathString = ", ".join(categoriesPath)

                dep = str(dep[10:]).split(':')
                cpeDependecyName = dep[0]
                cpeDependecyVersion = " "
                if(len(dep)> 2) : cpeDependecyVersion = dep[2]
                if(len(dep)> 1): cpeDependecyName =dep[0]+':'+dep[1]

                if cve in valid_cwe:
                    for rep in valid_cwe[cve]:
                        writer.writerow([cve, rep, cwe, severity, cpeDependecyName, cpeDependecyVersion, description, ', '.join(relatedAttacks),
                                     availability, confidentiality, integrity, accessControl, nonRepudiation, other, categoriesPathString])
    
    l.close()

valid_cwe = {}

#with open('../../analysis/grouped_unique_cve_patterns_final_before_after.csv', 'r') as b:
with open('../../analysis/filtering_sample/grouped_unique_cve_patterns_final_before_after.csv', 'r') as b:
    data3 = csv.reader(b)
    for row in data3:
        if row[1] == 'CVE':
            continue
        if row[1] not in valid_cwe:
            valid_cwe[row[1]] = [row[5]]
        else:
            valid_cwe[row[1]].append(row[5])


#File that already contains informations using the cwe name   
with open('../../analysis/cwefull-FINAL-fixed-FINAL.csv', 'r') as b:
    data3 = csv.reader(b)
    readers = list(data3)
    
    g = open('../../analysis/nvd_sample/nvd-fixed-fixed-FINAL-before_after_issue_link.csv', 'w')
    writer = csv.writer(g)   
    
    row=['CVE ID', 'GHIssue', 'CWE name', 'CVE severity', 'CPE dependency name ', 'CPE dependency version', 'Description' ,
         'Related attacks', 'Availability', 'Confidentiality', 'Integrity', 'Access Control', 'Non-Repudiation', 'Other', 'Categories path']
    writer.writerow(row)

    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2002.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2003.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2007.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2009.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2013.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2014.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2015.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2016.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2017.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2018.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2019.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2020.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2021.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2022.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2023.json', readers, writer, valid_cwe)
    readFileaAndWrite('../../analysis/nvd/nvdcve-1.1-2024.json', readers, writer, valid_cwe)
    
