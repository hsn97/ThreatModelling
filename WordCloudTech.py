import wordcloud as w
import numpy as np
import matplotlib.pyplot as plt
from numpy.ma import count

list_priority_tech = {"Gather Victim Identity Information": 1, "Obtain Capabilities": 2, "Acquire Infrastructure": 2,
                      "Compromise Infrastructure": 1, "External Remote Services": 2,
                      "Trusted Relationship": 3,
                      "Valid Accounts": 4, "Exploitation for Client Execution": 3, "User Execution": 1,
                      "Command and Scripting Interpreter": 1, "External Remote Services": 3, "Create Account": 2,
                      "Boot or Logon Autostart Execution": 2, "Account Manipulation": 1,
                      "Exploitation for Privilege Escalation": 2, "Subvert Trust Controls": 1, "Masquerading": 3,
                      "Multi-Factor Authentication Request Generation": 4, "Credentials from Password Stores": 1,
                      "OS Credential Dumping": 1, "Process Discovery": 5, "File and Directory Discovery": 2,
                      "Permission Groups Discovery": 1, "System Information Discovery": 2, "Account Discovery": 1,
                      "Remote Services": 1, "Data from Local System": 1, "Archive Collected Data": 1,
                      "Data from Information Repositories": 4, "Email Collection": 1, "Ingress Tool Transfer": 3,
                      "Web Service": 1, "Application Layer Protocol": 1, "Exfiltration Over Alternative Protocol": 1,
                      "Account Access Removal": 1, "Data Destruction": 1,
                      "Credential Access": 1, "Email Addresses": 1, "Tool Acquisition": 3, "Malware": 2, "Domain": 6,
                      "Email Accounts": 1,
                      "Spearphishing Attachment": 5, "Spearphishing Link": 4, "Spearphishing via Service": 2,
                      "Cloud Accounts": 4, "Malicious File": 2, "Malicious Link": 1, "Windows Command Shell": 1,
                      "Registry Run Keys / Startup Folder": 3,
                      "Additional Cloud Roles": 1, "Code Signing": 2, "Match Legitimate Name or Location": 1,
                      "Credentials from Web Browsers": 1, "DCSync": 2, "Domain Account": 2, "Domain Groups": 1,
                      "Remote Desktop Protocol": 1, "Archive via Utility": 1, "Code Repositories": 2,
                      "Remote Email Collection": 1, "Bidirectional Communication": 1, "Web Protocols": 1,
                      "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol": 2
                      }
# frequencies = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
#                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3]

# print(list_priority_tech.index("Domain"))

# Wordcloud asks for a string, and I have tried separating the terms with ',' and '~'

# text = ''
# for i, word in enumerate(ingredients):
#     text = text + frequencies[i] * (word + ',')

# wordcloud = w.WordCloud(collocations = False).generate(text)

print(count(list_priority_tech))
# d = dict(zip(ingredients, frequencies))
wordcloud = w.WordCloud(width = 3000, height = 2000, random_state=1, background_color='white', colormap='Set2',
                        collocations=False).generate_from_frequencies(list_priority_tech)

#
plt.imshow(wordcloud)
plt.axis("off")
plt.show()
