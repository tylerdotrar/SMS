#!/usr/bin/env python3.8

__author__ = 'gaytan','tiler'

import json
import flask
import argparse
from flask import request, jsonify

app = flask.Flask(__name__)
app.config['CONFIG_PATH'] = './var' # Currently not used

global messages 
messages = [] # {message : x1, targetUser : y2, sender : z3, etc.}

global credentials
credentials = {} # {username : x2, password : y2, etc.}

# Verify Content
def json_check(info):
    if 'message' not in info:
        return 'NO MESSAGE PRESENT'
    elif 'targetUser' not in info:
        return 'NO TARGETUSER PRESENT'
    else:
        return True

# Verify Credentials
def cred_check(content, field):
    user = content[field]
    if credentials == {}:
        return 'NULL CREDENTIAL LIST'
    elif user not in credentials:
        return 'FAILED USER AUTH'
    elif content['password'] != credentials[user]:
        return 'WRONG PASSWORD'
    else:
        return True


### VIEW PENDING MESSAGES ###
@app.route('/master', methods=['GET'])
def root():
    if messages == []:
        return 'NO PENDING MESSAGES'
    return json.dumps(messages)


### CREDENTIAL LOGGING ###
@app.route('/update', methods=['POST'])
def Update():
    global credentials
    body = request.get_json()

    credentials.update({body['username']:body['password']})
    return 'USER "' + body['username'] + '" CREDENTIALS UPDATED'


### SEND ### 
@app.route('/send', methods=['POST'])
def Send():
    global messages
    info = request.get_json()

    result = json_check(info)
    if result != True:
        return "SEND-ERROR: " + result

    cred_err = cred_check(info,'sender')
    if cred_err != True:
        return "CRED-ERROR: " + cred_err

    del info['password']
    messages.append(info)
    return 'SUCCESS: MESSAGE SENT TO "' + info['targetUser'] + '"'
    

### RETRIEVE ###
@app.route('/retrieve', methods=['GET'])
def Retrieve():
    global messages
    info = request.get_json()
    
    if 'targetUser' not in info:
        return 'RETR-ERROR: NO TARGETUSER PRESENT'
    
    cred_err = cred_check(info,'targetUser')
    if cred_err != True:
        return "CRED-ERROR: " + cred_err

    msgs = []
    for m in messages:
        if m['targetUser'] == info['targetUser']:
            msgs.append(m)
            messages.remove(m)
                
    if msgs == []:
        return 'NO MESSAGES FOR "' + info['targetUser'] + '"'
    return json.dumps(msgs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', type=str, default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--nodebug', action='store_false', default=True)
    parser.add_argument('--ssl', action='store_const', const='adhoc', default=None)
    args = parser.parse_args()
    
    app.run(host=args.ip, port=args.port, ssl_context=args.ssl, debug=args.nodebug)