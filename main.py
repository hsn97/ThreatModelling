from pyattck import Attck
import pandas as pd
import csv

from pandas import *
from pandas.io.json import json_normalize


def find_techniques(actor):
    attack = Attck()
    print("Finding techniques used by {}".format(actor.name))
    for technique in actor.techniques:
        # print(technique.id)
        # print(technique.name)
        find_mitigations(actor, technique)
        find_tools(technique)
        find_malware(technique)
        #find_detections(actor, technique)

        with open('TG_Tech.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([actor.name, technique.name, technique.description])


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
    f = open(file_name, "w")
    fieldnames = []
    for column_name in column_list:
        fieldnames.append(column_name)

    writer = csv.DictWriter(
    f, fieldnames)
    writer.writeheader()
    f.close()



def main():
    attack = Attck()

    list_actors = ["EXOTIC LILY", "APT29", "APT12", "APT17", "APT18", "APT19", "APT1", "LAPSUS$", "Winnti Group"]

    count = 0

    # Creating TG- Technique - Technique Description CSV
    create_csv_file("TG_Tech.csv", ["Threat Group", "Technique Used", "Technique Description"])

    # Creating TG - Technique - Mitigation CSV
    create_csv_file("TG_Tech_Mit.csv", ["Threat Group", "Technique Used", "Mitigation", "Mitigation Description"])

    # Creating TG - Tools CSV
    create_csv_file("TG_Tools.csv", ["Threat Group", "Tools Used"])

    #Creating Techniques - Tools CSV
    create_csv_file("Tech_Tools.csv", ["Techniques", "Tools Used"])

	#Creating TG - Malware CSV
    create_csv_file("TG_Malware.csv", ["Threat Group", "Malware Used"])
    
    #Creating Techniques - Tools CSV
    create_csv_file("Tech_Malware.csv", ["Techniques", "Malware Used"])

    #Creating TG-Techniques - Detections CSV
    create_csv_file("TG_Tech_Detect.csv", ["Threat Group","Techniques Used", "Detection"])

    # Iterate through list of threat actors and find techniques, tools, malware used by each
	#Mitigations are found through a nested function in the find_techniques()

    for actor in attack.enterprise.actors:
        if actor.name in list_actors:  # Iterate through list of actors
            print("Found {}".format(actor.name))
            find_techniques(actor)
            find_tools_actor(actor)
            find_malware_actor(actor)


if __name__ == '__main__':
    main()

