import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

df1 = pd.read_csv("C://Users//Husain//PycharmProjects//pythonProject//Tech_Tools.csv", usecols=['Techniques', 'Tools'])

# print(df.head())

df = df1.groupby(['Tools'])['Techniques'].count().\
  reset_index( name='Count').sort_values(['Count'], ascending=True)

print(df)

col = "Tools"
min = 20


s= df1.Tools.value_counts().gt(min)
hdf = df1.loc[df1.Tools.isin(s[s].index)]

print(hdf)

hdf.groupby(['Tools'])['Techniques'].count().reset_index(
  name='Count').sort_values(['Count'], ascending=True).plot\
    .bar(x='Tools', figsize=(15,8), rot=35, title='Most Used Tools')


plt.show()

