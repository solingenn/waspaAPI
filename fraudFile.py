#!/usr/bin/env python3

import yaml
import xml.dom.minidom as xmlDom
import xml.etree.ElementTree as ET
import requests
import argparse

def login(url, headers, action, version, wasp, password, trace):

    # XML string for login
    loginData = '''<?xml version="1.0" encoding="utf8"?>
    <loginrequest>
        <action>''' + str(action) + '''</action>
        <version>''' + str(version) + '''</version>
        <wasp>''' + str(wasp) + '''</wasp>
        <password>''' + str(password) + '''</password>
        <trace>''' + str(trace) + '''</trace>
    </loginrequest>'''

    try:
        # sending login request to waspa API
        loginRequest = requests.post(url, data={'xml':loginData}, headers=headers).text

        return loginRequest
    except requests.ConnectionError:
        print('Login request connection error! Try again.')
        return None

def getFraudFile(output, debug, url, headers, action, version, wasp, password, trace):

    # checking if -o parameter has been called
    if output is not None:
        filename = output[0]
    else:
        filename = 'waspablocklist.txt'

    session = login(url, headers, action, version, wasp, password, trace)
    # checking login() return value
    if session is None:
        return None
    
    # parsing XML from request string and retrieving session ID
    loginRsp = ET.fromstring(session)
    sessionId = loginRsp[1].text

    try:
        # XML string for requesting fraud file(blocklist)
        fraudFileRequest = '''<?xml version='1.0' encoding='UTF-8'?>
        <request>
            <action>GetFraudFile</action>
            <session_id>''' + sessionId + '''</session_id>
        </request>'''

        # sending request for fraud file to waspa API
        fraudRequest = requests.post(url, data={'xml':fraudFileRequest}, headers=headers).text

        # check if --debug option is called
        if debug:
            # prettify login response XML string
            loginResponse = xmlDom.parseString(session)
            loginXML = loginResponse.toprettyxml()

            # print XML response to console
            print('##### Login XML debug #####\n' + loginXML)

            # prettify fraud file response XML string
            fraudResponse = xmlDom.parseString(fraudRequest)
            fraudFileXML = fraudResponse.toprettyxml()

            # print XML response to console
            print('##### Blocklist XML debug #####\n' + fraudFileXML)
            print('Debug successful!')

        # parsing XML from request string and retrieving content (blocklist)
        fraudXML = ET.fromstring(fraudRequest)
        content = fraudXML[2].text

        # save content to waspablocklist.txt
        with open(filename, 'w') as blocklist:
            blocklist.write(content)

        print('Waspa blocklist successfuly updated!')
    except requests.ConnectionError:
        print('Fraud request connection error. Try again.')

def main(): 

    with open('config.yml', 'r') as cnf:
        doc = yaml.load(cnf)

    # data from config.yml file
    url = doc["live"]["live_URL"]
    action = doc["live"]["loginrequest"]["action"]
    version = doc["live"]["loginrequest"]["version"]
    wasp = doc["live"]["loginrequest"]["wasp_id"]
    password = doc["live"]["loginrequest"]["password"]
    trace = doc["live"]["loginrequest"]["trace"]

    # setting options for arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', help='save API XML response into XML files', action='store_true')
    parser.add_argument('-o', '--output', help='user defined blocklist filename', nargs=1)

    args = parser.parse_args()
    debug = args.debug
    output = args.output

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    getFraudFile(output, debug, url, headers, action, version, wasp, password, trace)

if __name__ == "__main__":
    main()
