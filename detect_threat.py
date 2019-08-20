# !usr/bin/env python3

# =====================================================
#  Threat Research - Hiring project for Avast Software
#
#  Author: Lubomir Svehla <lubomir.svehla@gmail.com>
#
#  detect_threat.py created: 2019-Jul-27
# =====================================================

import sys
import re
import zipfile
from time import sleep
from itertools import cycle
import requests
import json


class SazFile:

    def __init__(self, filename):
        self.filename = filename
        self._zipfile = None

    @property
    def zipfile(self):
        if self._zipfile is None:
            try:
                self._zipfile = zipfile.ZipFile(self.filename)
            except FileNotFoundError:
                print("Error: File with analyzed data was not found!")
                exit(1)
            except zipfile.BadZipFile:
                print("Error: Analyzed file is not a zip file!")
                exit(1)
        return self._zipfile

    @property
    def html(self):
        return self.zipfile.read('_index.htm').decode('utf-8')


class URLs:

    def __init__(self):
        self._urls = []
        self._malicious_urls = []
        self._not_reported_urls = []

    def get_urls(self):
        return self._urls

    def get_malicious_urls(self):
        return self._malicious_urls

    def get_not_reported_urls(self):
        return self._not_reported_urls

    def construct_url(self, url_parts):
        if url_parts[0] == "HTTPS":
            self._urls.append("https://" + url_parts[1] + url_parts[2])
        else:
            self._urls.append("http://" + url_parts[1] + url_parts[2])

    # sends requests to virustotal.com API and checks the response to find if the URL was detected as malicious
    # if URL was not in virustotal.com database yet, it is automatically scanned and marked to be checked again
    def _check_url(self, api_key, resource, url):
        params = {'apikey': api_key, 'resource': resource, 'scan': 1}
        response = requests.get(url, params=params).json()

        if response["verbose_msg"] == "Scan request successfully queued, come back later for the report":
            self._not_reported_urls.append(resource)
        else:
            if response["positives"]:
                if resource not in self.get_malicious_urls():
                    self._malicious_urls.append(resource)
                    print("Checking URL:", resource, "Threat detected by:", sep='\n')
                    for av_engine, data in response["scans"].items():
                        if data['detected']:
                            print(av_engine)
            else:
                print("Checking URL:", resource, "No threat was detected", sep='\n')
            print()
            if resource in self.get_not_reported_urls():
                self.get_not_reported_urls().remove(resource)

    def find_malicious_urls(self, resources, keys):
        key_iterator = cycle(keys)
        key = next(key_iterator)
        url = 'https://www.virustotal.com/vtapi/v2/url/report'

        for resource in resources:
            # switch between API keys, until a free one is found
            while True:
                try:
                    self._check_url(key, resource, url)
                except json.decoder.JSONDecodeError:
                    key = next(key_iterator)
                else:
                    break

    def check_not_reported_urls(self, keys):
        while self.get_not_reported_urls():
            print("waiting to scan urls that were not reported yet...\n")
            sleep(5)
            self.find_malicious_urls(self.get_not_reported_urls(), keys['api_keys'])


def parse_api_keys(json_str):
    try:
        api_keys = json.loads(json_str)
    except json.decoder.JSONDecodeError:
        print("Error: File with the api keys has to be formated in .json!")
        exit(1)
    if 'api_keys' not in api_keys:
        print("Error: JSON has to contain element 'api_keys'!")
        exit(1)
    if not isinstance(api_keys['api_keys'], list):
        print("Error: Value of 'api_keys' key has to be instance of list object!")
        exit(1)
    if len(api_keys['api_keys']) < 1:
        print("Error: The list contains no keys!")
        exit(1)
    return api_keys


def print_help():
    print("To use the program, you have to specify path to analyzed .saz file.",
          "Optionally, you can also specify path to .json file, containing set of API keys",
          "Examples:",
          "$ python3.5 ./detect_threat.py RigEK-Fobos-16-7-2019.saz",
          "$ python3.5 ./detect_threat.py RigEK-Fobos-16-7-2019.saz api_keys.json", sep='\n')


def main():
    if len(sys.argv) < 2 or (len(sys.argv) == 2 and sys.argv[1] == '-h'):
        print_help()
        exit(0)

    saz_file = SazFile(sys.argv[1])
    urls = URLs()

    # regex to parse URLs from html file:
    # It looks for field with HTTP/HTTPS and two following fields, containing hostname and rest of the URL
    urls_parts = re.findall("<td>(HTTP[S]?)</td><td>(.*?)</td><td>(.*?)</td>", saz_file.html)
    for record in urls_parts:
        urls.construct_url(record)

    if len(sys.argv) > 2:
        json_path = sys.argv[2]
    else:
        json_path = 'api_keys.json'
    try:
        with open(json_path, 'r') as json_file:
            json_str = json_file.read()
    except FileNotFoundError:
        print("Error: File with keys was not found!")
        exit(1)
    api_keys = parse_api_keys(json_str)

    urls.find_malicious_urls(urls.get_urls(), api_keys['api_keys'])
    urls.check_not_reported_urls(api_keys['api_keys'])


if __name__ == '__main__':
    main()
