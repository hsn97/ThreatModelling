import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

df1 = pd.read_csv("TG_Tech_Mit.csv", usecols=['Threat Group', 'Mitigation'])

# print(df.head())

df = df1.groupby(['Mitigation'])['Threat Group'].count().\
  reset_index( name='Count').sort_values(['Count'], ascending=True)

print(df)

col = "Mitigation"
min = 20


s= df1.Mitigation.value_counts().gt(min)
hdf = df1.loc[df1.Mitigation.isin(s[s].index)]

print(hdf)

hdf.groupby(['Mitigation'])['Threat Group'].count().reset_index(
  name='Count').sort_values(['Count'], ascending=True).plot\
    .bar(x='Mitigation', figsize=(15,8), rot=35, title='Mitigation Priority List')


plt.show()

