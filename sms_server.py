#!/usr/bin/env python3.8

__author__ = 'gaytan','tiler'

import json
import flask
import argparse
from datetime import datetime
from flask import request, jsonify

app = flask.Flask(__name__)

global messages 
messages = [] # {message: x, targetUser : x, sender : x, timestamp : x}

def json_check(info):
    if 'uid' not in info:
        return 'NO IDENTIFIER PRESENT'
    elif info['uid'] != 'seventeenthirtyeight':
        return 'INVALID IDENTIFIER'
    elif 'message' not in info:
        return 'NO MESSAGE PRESENT'
    elif 'targetUser' not in info:
        return 'NO TARGETUSER PRESENT'
    else:
        return True


### MASTER ###
@app.route('/master', methods=['GET'])
def root():
    if messages == []:
        return 'NO PENDING MESSAGES'
    return json.dumps(messages)


### SEND ### 
@app.route('/send', methods=['POST'])
def Send():
    global messages
    info = request.get_json()

    result = json_check(info)
    if result != True:
        return "SEND-ERROR: " + result
        
    content = request.get_json()
    messages.append(content)
    return 'SUCCESS: MESSAGE SENT TO ' + '"' + info['targetUser'] + '"'
    

### RETRIEVE ###
@app.route('/retrieve', methods=['GET'])
def Retrieve():
    global messages
    info = request.get_json()
    
    if 'uid' not in info:
        return 'NO IDENTIFIER PRESENT'
    elif info['uid'] != 'seventeenthirtyeight':
        return 'INVALID IDENTIFIER'
    if 'targetUser' not in info:
        return 'RETRIEVE-ERROR: NO TARGETUSER PRESENT'
        
    msgs = []
    for m in messages:
        if m['targetUser'] == info['targetUser']:
            msgs.append(m)
            messages.remove(m)
                
    if msgs == []:
        return 'NO MESSAGES FOR ' + '"' + info['targetUser'] + '"'
    return json.dumps(msgs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', type=str, default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--nodebug', action='store_false', default=True)
    parser.add_argument('--ssl', action='store_const', const='adhoc', default=None)
    args = parser.parse_args()
    
    app.run(host=args.ip, port=args.port, ssl_context=args.ssl, debug=args.nodebug)
