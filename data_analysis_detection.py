import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

df1 = pd.read_csv("TG_Tech_Detect.csv", usecols=['Threat Group', 'Detection'])

# print(df.head())

df = df1.groupby(['Detection'])['Threat Group'].count().\
  reset_index( name='Count').sort_values(['Count'], ascending=True)

print(df)

col = "Detection"
min = 30


s= df1.Detection.value_counts().gt(min)
hdf = df1.loc[df1.Detection.isin(s[s].index)]

print(hdf)

hdf.groupby(['Detection'])['Threat Group'].count().reset_index(
  name='Count').sort_values(['Count'], ascending=True).plot\
    .bar(x='Detection', figsize=(15,8), rot=35, title='Detection Priority List')


plt.show()

