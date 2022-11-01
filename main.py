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
        # find_tools(technique)
        # find_malware(technique)
        find_controls(actor, technique)

        with open('TG_Tech.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([actor.name, technique.name, technique.description])

        for subtechnique in technique.subtechniques:
            print("Finding sub techniques for technique {}".format(technique.name))
            # print(subtechnique.id)
            # print(subtechnique.name)
            find_mitigations(actor, subtechnique)
            # find_tools(subtechnique)
            # find_malware(subtechnique)
            find_controls(actor, subtechnique)

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
        print(tool.name)


def find_malware(technique):
    attack = Attck()
    print("Finding Malware used for {}".format(technique.name))

    for malware in technique.malwares:
        print(malware.name)


def find_controls(actor, technique):
    attack = Attck()
    print("Finding NIST controls used for {}".format(technique.name))

    for control in technique.controls:
        # print(control.name)

        with open('TG_Tech_Con.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([actor.name, technique.name, control.name, control.description])


def main():
    attack = Attck()

    list_actors = ["EXOTIC LILY"]
    #
    # for technique in attack.enterprise.techniques:
    #     print(technique.id)
    #     print(technique.name)
    #     for subtechnique in technique.subtechniques:
    #         print(subtechnique.id)
    #         print(subtechnique.name)
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


    # read contents of csv file

    for actor in attack.enterprise.actors:
        if actor.name in list_actors:  # Iterate through list of actors
            print("Found {}".format(actor.name))
            find_techniques(actor)

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
