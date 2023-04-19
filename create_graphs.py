from pyattck import Attck
import pandas as pd
import csv
import os

from pandas import *
from pandas.io.json import json_normalize

import numpy as np
import matplotlib.pyplot as plt


def create_mitigation_graph():
	print("Creating the Mitigation Graph")

	df1= pd.read_csv("DataFiles/TG_Tech_Mit.csv", usecols=['Threat Group', 'Mitigation'])
	
	df = df1.groupby(['Mitigation'])['Threat Group'].count().reset_index( name = 'Count').sort_values(['Count'], ascending=True)
	print(df)
	
	col = "Mitigation"
	min = 15
	
	s= df1.Mitigation.value_counts().gt(min)
	hdf = df1.loc[df1.Mitigation.isin(s[s].index)]

	#print(hdf)

	hdf.groupby(['Mitigation'])['Threat Group'].count().reset_index(name='Count').sort_values(['Count'], ascending = True).plot.barh(x ="Mitigation", title = "High Frequency Mitigations vs Number of Techniques Mitigated Against")

	#bar.gca().invert_yaxis()
	plt.tight_layout()
	plt.savefig("Graphs/MitigationPriorityGraph.svg", bbox_inches='tight')
	plt.show()
	

def create_tools_graph():
	print("Creating the Tools Graph")

	df1= pd.read_csv("DataFiles/Tech_Tools.csv", usecols=['Techniques', 'Tools'])
	
	df = df1.groupby(['Tools'])['Techniques'].count().reset_index( name = 'Count').sort_values(['Count'], ascending=True)
	#print(df)

	col = "Tools"
	min = 10
	
	s= df1.Tools.value_counts().gt(min)
	hdf = df1.loc[df1.Tools.isin(s[s].index)]

	#print(hdf)

	hdf.groupby(['Tools'])['Techniques'].count().reset_index(name='Count').sort_values(['Count'], ascending = True).plot.barh(x ="Tools", title = "Most Used Tools")
	plt.savefig("Graphs/ToolsUsedGraph.svg", bbox_inches='tight')
	plt.show()
	

def create_malware_graph():
	print("Creating the Malware Graph")

	df1= pd.read_csv("DataFiles/Tech_Malware.csv", usecols=['Techniques', 'Malware'])
	
	df = df1.groupby(['Malware'])['Techniques'].count().reset_index( name = 'Count').sort_values(['Count'], ascending=True)
	#print(df)

	col = "Malware"
	min = 45
	
	s= df1.Malware.value_counts().gt(min)
	hdf = df1.loc[df1.Malware.isin(s[s].index)]

	#print(hdf)

	hdf.groupby(['Malware'])['Techniques'].count().reset_index(name='Count').sort_values(['Count'], ascending = True).plot.barh(x ="Malware", title = "Most Used Malware")
	
	plt.savefig("Graphs/MalwareUsedGraph.svg", bbox_inches='tight')
	plt.show()
	


def main():

	create_mitigation_graph()
	create_tools_graph()
	create_malware_graph()


if __name__ == '__main__':
	main()
