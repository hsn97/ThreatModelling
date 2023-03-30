#You only need to import pyattck and csv to run the script

from pyattck import Attck
import csv

#pandas is required if you want run the find_detections function
#The detections function in incomplete

import pandas as pd
from pandas import *
from pandas.io.json import json_normalize

#See main function at bottom of script for order of operations

def find_techniques(actor):
    attack = Attck()
    print("Finding techniques used by {}".format(actor.name))
    for technique in actor.techniques:
        # print(technique.id)
        # print(technique.name)
        find_mitigations(actor, technique)
        find_tools(technique)
        find_malware(technique)
        # find_controls(actor, technique)
        find_detections(actor, technique)

        with open('TG_Tech.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([actor.name, technique.name, technique.description])

        for subtechnique in technique.subtechniques:
            print("Finding sub techniques for technique {}".format(technique.name))
            # print(subtechnique.id)
            # print(subtechnique.name)
            find_mitigations(actor, subtechnique)
            find_tools(subtechnique)
            find_malware(subtechnique)
            # find_controls(actor, subtechnique)
            find_detections(actor, subtechnique)

            with open('TG_Tech.csv', 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([actor.name, subtechnique.name, subtechnique.description])


def find_mitigations(actor, technique):
    attack = Attck()
    print("Finding Mitigations for {}".format(technique.name))

    for mitigation in technique.mitigations:
        # print(mitigation.name)

        with open('TG_Tech_Mit.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([actor.name, technique.name, mitigation.name, mitigation.description])


def find_tools(technique):
    attack = Attck()
    print("Finding Tools used for {}".format(technique.name))

    for tool in technique.tools:
        # print(tool.name)

        with open('Tech_Tools.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([technique.name, tool.name])


def find_malware(technique):
    attack = Attck()
    print("Finding Malware used for {}".format(technique.name))

    for malware in technique.malwares:
        # print(malware.name)

        with open('Tech_Malware.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([technique.name, malware.name])


def find_malware_actor(actor):
    attack = Attck()
    print("Finding Malware used for {}".format(actor.name))

    for malware in actor.malwares:
        # print(malware.name)

        with open('TG_Malware.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([actor.name, malware.name])


def find_tools_actor(actor):
    attack = Attck()
    print("Finding Tools used by {}".format(actor.name))

    for tool in actor.tools:
        # print(tool.name)

        with open('TG_Tools.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([actor.name, tool.name])


def find_controls(actor, technique):
    attack = Attck()
    print("Finding NIST controls used for {}".format(technique.name))

    for control in technique.controls:
        # print(control.name)

        with open('TG_Tech_Con.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([actor.name, technique.name, control.name, control.description])


def find_detections(actor, technique):
    print("Finding Detections for {}".format(technique.name))
    ctr = 0
    # print("Detections Details Data Source: {}".format(technique.possible_detections))
    detection_dict = technique.possible_detections
    for i in detection_dict or []:
        ctr += 1
        # print("{}. Detection method is: {}".format(ctr, i))
        # print(i['data_source'])
        if 'data_source' in i:
            for key in i:
                # print("Nested Dictionary found - {}".format(i[key]))
                nested_dict = i[key]
                if 'data_source' in nested_dict and nested_dict['data_source'] == nested_dict['data_source']:
                    # print("Nested value of data source is - {}".format(nested_dict['data_source']))
                    data_source = nested_dict['data_source']
                    with open('TG_Tech_Detect.csv', 'a', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow([actor.name, technique.name, data_source])
                    # print("Source 1 {}".format(data_source))
                elif 'data_source' not in nested_dict:
                    if (len(nested_dict)) == 2:
                        detections_list = list(nested_dict)
                        # print("Final Detection is {}".format(detections_list[1]))
                        data_source = detections_list[1]
                        # print("Source 2 {}".format(data_source))
                        with open('TG_Tech_Detect.csv', 'a', newline='') as file:
                            writer = csv.writer(file)
                            writer.writerow([actor.name, technique.name, data_source])
                    else:
                        # print(*nested_dict)
                        detections_list = list(nested_dict)
                        data_source = detections_list[0]
                        if data_source != 'title' and data_source != 'action':
                            if data_source == '200-500':
                                data_source = 'PowerShell Logs'
                            # print("Source 3 {}".format(data_source))
                            with open('TG_Tech_Detect.csv', 'a', newline='') as file:
                                writer = csv.writer(file)
                                writer.writerow([actor.name, technique.name, data_source])


#Function to create a csv file with given column names and file name
def create_csv_file(file_name, column_list):

    f = open("file_name"+".csv", "w")
    fieldnames = []
    for column_name in column_list:
        fieldnames.append(column_name)

    writer = csv.DictWriter(
        f, fieldnames)
    writer.writeheader()
    f.close()






#Start of Execution

def main():
    attack = Attck()

    #Define a list of threat actors - All other functions work on these actors

    list_actors = ["EXOTIC LILY", "APT29", "APT12", "APT17", "APT18", "APT19", "APT1", "LAPSUS$", "Winnti Group"]
    #
    # for technique in attack.enterprise.techniques:
    #     print(technique.id)
    #     print(technique.name)
    #     for subtechnique in technique.subtechniques:
    #         print(subtechnique.id)
    #         print(subtechnique.name)

    create_csv_file("TG_Tech.csv", column_list = ["Threat Group", "Technique Used", "Technique Description"])

    count = 0
    # Creating TG- Technique - Technique Description CSV
    f = open("TG_Tech.csv", "w")
    writer = csv.DictWriter(
        f, fieldnames=["Threat Group", "Technique Used", "Technique Description"])
    writer.writeheader()
    f.close()

    # Creating TG - Technique - Mitigation CSV
    f = open("TG_Tech_Mit.csv", "w")
    writer = csv.DictWriter(
        f, fieldnames=["Threat Group", "Technique Used", "Mitigation", "Mitigation Description"])
    writer.writeheader()
    f.close()

    # Creating TG - Technique - Controls CSV
    f = open("TG_Tech_Con.csv", "w")
    writer = csv.DictWriter(
        f, fieldnames=["Threat Group", "Technique Used", "NIST Controls", "Control Description"])
    writer.writeheader()
    f.close()

    # Creating TG - Tools CSV
    f = open("TG_Tools.csv", "w")
    writer = csv.DictWriter(
        f, fieldnames=["Threat Group", "Tools Used"])
    writer.writeheader()
    f.close()

    f = open("Tech_Tools.csv", "w")
    writer = csv.DictWriter(
        f, fieldnames=["Techniques", "Tools Used"])
    writer.writeheader()
    f.close()

    f = open("TG_Malware.csv", "w")
    writer = csv.DictWriter(
        f, fieldnames=["Threat Group", "Malware Used"])
    writer.writeheader()
    f.close()

    f = open("Tech_Malware.csv", "w")
    writer = csv.DictWriter(
        f, fieldnames=["Technique", "Malware Used"])
    writer.writeheader()
    f.close()

    f = open("TG_Tech_Detect.csv", "w")
    writer = csv.DictWriter(
        f, fieldnames=["Threat Group", "Technique Used", "Detection"])
    writer.writeheader()
    f.close()
    # read contents of csv file

    for actor in attack.enterprise.actors:
        if actor.name in list_actors:  # Iterate through list of actors
            print("Found {}".format(actor.name))
            find_techniques(actor)
            find_tools_actor(actor)
            find_malware_actor(actor)

        # count += 1
        # if count == 2:
        #     break
        # print(actor.name)
        # print(actor.id)

        # print(actor.known_tools)
        # print("The Threat Group - {} targets -----------------".format(actor.name))
        # print(actor.targets)
        # print("The Threat Group - {} is based out of -----------------".format(actor.name))
        # print(actor.country)
        # print("The Threat Group - {} - Atrribution -----------------".format(actor.name))
        # print(actor.attribution_links)
        # technique_list = []
        # for technique in actor.techniques:
        #     print("For Threat Group {}".format(actor.name))
        #     print(technique.id)
        #     print(technique.name)
        #     # print("Detection could done by: {}".format(technique.possible_detections))
        #     technique_list.append(technique)
        #     # for mitigation in technique.mitigations:
        #     #     print("The mitigations for the technique {} is {}".format(technique.name, mitigation.name))
        #
        # print("The techniques used by Threat Group {} are".format(actor.name))
        # print(technique_list)
        # # for tool in attack.malwares:
        # #     print("The Threat Group - {} uses the tools {}".format(actor.name, tool.name))
        # #     print(tool.id)
        # #     print(tool.name)


if __name__ == '__main__':
    main()
