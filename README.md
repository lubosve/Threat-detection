# Threat detect

This program is able to parse urls from .saz archive and check for malicious ones between them. Detection is done by using virustotal.com public API for url report. 

## Implementation details

Program works with two objects. First of them manages the .saz file. The second one is used to store lists of scanned URLs and contains methods to manipulate with them.

Program first parses the data from html file inside .saz archive. Afterwards, the parsed data are merged into list of urls. 

Next step is loading .json file, containing API keys. Public API is limited to 4 requests in 1 minute. Therefore there is a file with 10 public keys provided with this script. User can modify the file or create a new one to insert more public keys, or add a private API key.

Cyclic key iterator is created to switch between API keys when the limit of requests per minute was reached. Program switches between the API keys until it finds a free one. URLs are checked one by one by sending requests to 'https://www.virustotal.com/vtapi/v2/url/report'. In case URL was not scanned by virustotal.com yet, it is stored in new list, which will be checked again later. 

virustotal.com API responds with data in JSON form. Malicious URLs are detected by looking at "positives" property, which symbolizes number of AV engines that detected it as a threat. All of the malicious urls are stored in a list. Furthermore, every url is printed out together with all the AV engines, which detected it as malicious.


## Prerequisites

Program is created in python3 and it uses libraries: sys, re, time, zipfile, itertools, requests and json.


## How to use

There is one compulsory and one optional parameter to run this program. The compulsory one is "checked_file", which represents the path to .saz file containg the fiddler capture with checked URLs. The second parameter is "api_keys", which is path to a .json file containing list of API keys to communicate with virustotal.com API. By default, file "api_keys.json" is used.

Full form is:
    python3 ./detect_threat.py <checked_file> <api_keys>

When no additional parameters are added, or parameter '-h' is used, a help message is printed.


### Example

Check for threats in urls contained in file RigEK-Fobos-16-7-2019.saz, using set of API keys from the default file "api_keys.json":

     $ python3.5 ./detect_threat.py RigEK-Fobos-16-7-2019.saz

