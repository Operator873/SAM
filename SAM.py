import requests
import sqlite3
import json
import re
from requests_oauthlib import OAuth1
from sopel import module

SAM_DB = "/home/ubuntu/.sopel/modules/SAM.db"
CONTACT_OP = "You are not configured. Please contact Operator873."

def addtomemory(user, payload):
    result = {}
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()
    
    check = c.execute('''SELECT * FROM memory WHERE user="%s" AND payload="%s";''' % (user, payload)).fetchall()
    
    if len(check) == 0:
    
        try:
            c.execute('''INSERT INTO memory VALUES("%s", "%s");''' % (user, payload))
            db.commit()
            result['status'] = "Success"
            result['data'] = "'" + payload + "' saved"
        except Exception as e:
            result['status'] = "Failure"
            result['data'] = str(e)
     
    else:
        result['status'] = "Success"
        result['data'] = "'" + payload + "' is already in memory." 
    
    db.close()
    
    return result
    
def getfrommemory(user):
    result = {}
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()
    
    try:
        result['data'] = c.execute('''SELECT payload FROM memory WHERE user="%s";''' % user).fetchall()
        result['status'] = "Success"
    except Exception as e:
        result['status'] = "Failure"
        result['data'] = str(e)
        
    db.close()
    
    return result

def delfrommemory(user, payload):
    result = {}
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()

    check = c.execute('''SELECT * FROM memory WHERE user="%s" AND payload="%s";''' % (user, payload)).fetchall()

    if len(check) > 0:
        c.execute('''DELETE FROM memory WHERE user="%s" AND payload="%s";''' % (user, payload))
        db.commit()
        result['status'] = "Success"
        result['data'] = "'" + payload + "' removed from memory."
    else:
        result['status'] = "Failure"
        result['data'] = "'" + payload + "' is not currently in memory for " + user + "."

    db.close()

    return result

def clearmemory(user):
    result = {}
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()
    
    try:
        c.execute('''DELETE FROM memory WHERE user="%s";''' % user)
        db.commit()
        result['status'] = "Success"
        result['data'] = "Memory Cleared."
    except Exception as e:
        result['status'] = "Failure"
        result['data'] = str(e)
        
    db.close()

    return result

def xmit(site, creds, payload, method):
    # This handles the post/get requests
    AUTH = OAuth1(creds[1], creds[2], creds[3], creds[4])
        
    if method == "post":
        return requests.post(site, data=payload, auth=AUTH).json()
    elif method == "get":
        return requests.get(site, params=payload, auth=AUTH).json()

def getWiki(project):
    # Define dbase connection
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()
    
    site = c.execute('''SELECT apiurl FROM wikis WHERE wiki="%s";''' % project).fetchone()[0]
    
    db.close()
    
    if site is None:
        return None
    else:
        return site

def getCSRF(bot, site, creds, type):
    reqtoken = {
        'action':"query",
        'meta':"tokens",
        'format':"json",
        'type':type
    }
    
    token = xmit(site, creds, reqtoken, "get")
    
    # Check for errors and return csrf
    if 'error' in token:
        bot.say(token['error']['info'])
        return False
    else:
        csrfToken = token['query']['tokens']['%stoken' % type]
        return csrfToken

def getCreds(name):
    # Setup dbase connection
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()
    
    # Get user credentials and prepare api url for use
    creds = c.execute('''SELECT * from auth where account="%s";''' % name).fetchall()[0]
    db.close()
    
    if creds is not None:
        return creds
    else:
        return None

def doBlock(bot, name, project, target, until, reason):
    creds = getCreds(name)
    
    if creds is None:
        bot.say(CONTACT_OP)
        return
    
    site = getWiki(project)
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
    
    if until == "indef" or until == "forever":
        until = "never"
    
    reqBlock = {
        "action": "block",
        "user": target,
        "expiry": until,
        "reason": reason,
        "token": csrfToken,
        "allowusertalk":"",
        "nocreate":"",
        "autoblock":"",
        "format": "json"
    }
    
    # Send block request
    block = xmit(site, creds, reqBlock, "post")
        
    if 'error' in block:
        reason = block['error']['code']
        if reason == "badtoken":
            bot.say("Received CSRF token error. Try again...")
        elif reason == "alreadyblocked":
            bot.say(target + " is already blocked. Use !reblock to change the current block.")
        elif reason == "permissiondenied":
            bot.say("Received permission denied error. Are you a sysop on " + project + "?")
        elif reason == "invalidexpiry":
            bot.say("The expiration time isn't valid. I understand things like 31hours, 1week, 6months, infinite, indefinite.")
        else:
            info = block['error']['info']
            code = block['error']['code']
            bot.say("Unhandled error: " + code + " " + info)
    elif 'block' in block:
        user = block['block']['user']
        expiry = block['block']['expiry']
        reason = block['block']['reason']
        bot.say(user + " was blocked until " + expiry + " with reason: " + reason)
    else:
        bot.say("Unknown error: " + block)

def doReblock(bot, name, project, target, until, reason):
    creds = getCreds(name)
    
    if creds is None:
        bot.say(CONTACT_OP)
        return
        
    site = getWiki(project)
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
    
    if until == "indef" or until == "forever":
        until = "never"
        
    reqBlock = {
        "action": "block",
        "user": target,
        "expiry": until,
        "reason": reason,
        "token": csrfToken,
        "allowusertalk":"",
        "nocreate":"",
        "autoblock":"",
        "reblock":"",
        "autoblock":"",
        "format": "json"
    }
    
    # Send block request
    block = xmit(site, creds, reqBlock, "post")
        
    if 'error' in block:
        reason = block['error']['code']
        if reason == "badtoken":
            bot.say("Received CSRF token error. Try again...")
        elif reason == "alreadyblocked":
            bot.say(target + " is already blocked. Use !reblock to change the current block.")
        elif reason == "permissiondenied":
            bot.say("Received permission denied error. Are you a sysop on " + project + "?")
        else:
            info = block['error']['info']
            bot.say("Unhandled error: " + info)
    elif 'block' in block:
        user = block['block']['user']
        expiry = block['block']['expiry']
        reason = block['block']['reason']
        bot.say(user + " was blocked until " + expiry + " with reason: " + reason)
    else:
        bot.say("Unknown error: " + block)

def doGlobalblock(bot, name, target, until, reason):
    creds = getCreds(name)
    
    if creds is None:
        bot.say(CONTACT_OP)
        return
        
    site = getWiki("metawiki")
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
    
    if until == "indef" or until == "forever":
        until = "never"
    
    block = {
            "action": "globalblock",
            "format": "json",
            "target": target,
            "expiry": until,
            "reason": reason,
            "alsolocal": True,
            "token": csrfToken
        }
    
    # Send block request
    gblock = xmit(site, creds, block, "post")
    
    if 'error' in gblock:
        failure = gblock['error']['info']
        bot.say("Block failed! " + failure)
    elif 'block' in gblock or 'globalblock' in gblock:
        user = gblock['globalblock']['user']
        expiry = gblock['globalblock']['expiry']
        bot.say("Block succeeded. " + user + " was blocked until " + expiry)
    else:
        bot.say("Unknown failure... " + gblock)

def doLock(bot, name, target, reason):
    creds = getCreds(name)
    
    if creds is None:
        bot.say(CONTACT_OP)
        return
    
    site = getWiki("metawiki")
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "setglobalaccountstatus")
    
    if csrfToken is False:
        return
        
    lockRequest = {
        "action":"setglobalaccountstatus",
        "format":"json",
        "user":target,
        "locked":"lock",
        "reason":reason,
        "token":csrfToken
    }
    
    # Send block request
    lock = xmit(site, creds, lockRequest, "post")
    
    if 'error' in lock:
        bot.say("lock failed! " + lock['error']['info'])
    else:
        bot.say(target + " locked.")

def doUnlock(bot, name, target, reason):
    creds = getCreds(name)
    
    if creds is None:
        bot.say(CONTACT_OP)
        return
    
    site = getWiki("metawiki")
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "setglobalaccountstatus")
    
    if csrfToken is False:
        return
        
    lockRequest = {
        "action":"setglobalaccountstatus",
        "format":"json",
        "user":target,
        "locked":"unlock",
        "reason":reason,
        "token":csrfToken
    }
    
    # Send block request
    lock = xmit(site, creds, lockRequest, "post")
    
    if 'error' in lock:
        bot.say("Unlock failed! " + lock['error']['info'])
    else:
        bot.say("Unlock succeeded. ")

def dorevokeTPA(bot, name, project, target, until, reason):
    creds = getCreds(name)
    
    if creds is None:
        bot.say(CONTACT_OP)
        return
    
    site = getWiki(project)
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
    
    if until == "indef" or until == "forever":
        until = "never"
        
    reqBlock = {
        "action": "block",
        "user": target,
        "expiry": until,
        "reason": reason,
        "token": csrfToken,
        "noemail":"",
        "nocreate":"",
        "reblock":"",
        "autoblock":"",
        "format": "json"
    }
    
    # Send block request
    block = xmit(site, creds, reqBlock, "post")
        
    if 'error' in block:
        reason = block['error']['code']
        if reason == "badtoken":
            bot.say("Received CSRF token error. Try again...")
        elif reason == "alreadyblocked":
            bot.say(target + " is already blocked. Use !reblock to change the current block.")
        elif reason == "permissiondenied":
            bot.say("Received permission denied error. Are you a sysop on " + project + "?")
        else:
            info = block['error']['info']
            bot.say("Unhandled error: " + info)
    elif 'block' in block:
        user = block['block']['user']
        expiry = block['block']['expiry']
        reason = block['block']['reason']
        bot.say(user + " was blocked until " + expiry + " with reason: " + reason)
    else:
        bot.say("Unknown error: " + block)

def doltaBlock(bot, name, project, target):
    creds = getCreds(name)
    
    if creds is None:
        bot.say(CONTACT_OP)
        return
    
    site = getWiki(project)
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
        
    reqBlock = {
        "action": "block",
        "user": target,
        "expiry": "1week",
        "reason": "LTA / Block evasion",
        "token": csrfToken,
        "noemail":"",
        "nocreate":"",
        "reblock":"",
        "autoblock":"",
        "format": "json"
    }
    
    # Send block request
    block = xmit(site, creds, reqBlock, "post")
        
    if 'error' in block:
        reason = block['error']['code']
        if reason == "badtoken":
            bot.say("Received CSRF token error. Try again...")
        elif reason == "alreadyblocked":
            bot.say(target + " is already blocked. Use !reblock to change the current block.")
        elif reason == "permissiondenied":
            bot.say("Received permission denied error. Are you a sysop on " + project + "?")
        else:
            info = block['error']['info']
            bot.say("Unhandled error: " + info)
    elif 'block' in block:
        user = block['block']['user']
        expiry = block['block']['expiry']
        reason = block['block']['reason']
        bot.say(user + " was blocked until " + expiry + " with reason: " + reason)
    else:
        bot.say("Unknown error: " + block)

def doSoftblock(bot, name, project, target, until, reason):
    creds = getCreds(name)
    
    if creds is None:
        bot.say(CONTACT_OP)
        return
    
    site = getWiki(project)
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
    
    if until == "indef" or until == "forever":
        until = "never"
        
    reqBlock = {
        "action": "block",
        "user": target,
        "expiry": until,
        "reason": reason,
        "token": csrfToken,
        "allowusertalk":"",
        "format": "json"
    }
    
    # Send block request
    block = xmit(site, creds, reqBlock, "post")
        
    if 'error' in block:
        reason = block['error']['code']
        if reason == "badtoken":
            bot.say("Received CSRF token error. Try again...")
        elif reason == "alreadyblocked":
            bot.say(target + " is already blocked. Use !reblock to change the current block.")
        elif reason == "permissiondenied":
            bot.say("Received permission denied error. Are you a sysop on " + project + "?")
        else:
            info = block['error']['info']
            bot.say("Unhandled error: " + info)
    elif 'block' in block:
        user = block['block']['user']
        expiry = block['block']['expiry']
        reason = block['block']['reason']
        bot.say(user + " was blocked until " + expiry + " with reason: " + reason)
    else:
        bot.say("Unknown error: " + block)

def doUnblock(bot, name, project, target, reason):
    creds = getCreds(name)
    
    if creds is None:
        bot.say(CONTACT_OP)
        return
    
    site = getWiki(project)
    
    if site is None:
        bot.say("I don't know that wiki.")
        return
    
    csrfToken = getCSRF(bot, site, creds, "csrf")
    
    if csrfToken is False:
        return
        
    reqBlock = {
        "action": "unblock",
        "user": target,
        "reason": reason,
        "token": csrfToken,
        "format": "json"
    }
    
    # Send block request
    unblock = xmit(site, creds, reqBlock, "post")
    
    if 'error' in unblock:
        reason = unblock['error']['info']
        bot.say(reason)
    elif 'unblock' in unblock:
        user = unblock['unblock']['user']
        reason = unblock['unblock']['reason']
        bot.say(user + " was unblocked with reason: " + reason)
    else:
        bot.say("Unhandled error: " + unblock)

def addUser(bot, name):
    # Setup dbase connection
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()
    
    # Check for user already existing
    check = c.execute('''SELECT * FROM auth WHERE account="%s";''' % name).fetchall()
    
    if len(check) != 0:
        bot.say("User already exists!")
        db.close()
        return
    else:
        # Add new user to database
        c.execute('''INSERT INTO auth VALUES("%s", NULL, NULL, NULL, NULL);''' % name)
        db.commit()
        db.close()
        bot.say("User added.")

def remUser(bot, name):
    # Setup dbase connection
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()
    
    # Check for user already existing
    check = c.execute('''SELECT * FROM auth WHERE account="%s";''' % name).fetchall()
    
    if len(check) == 0:
        bot.say("User does not exist!")
        db.close()
    else:
        c.execute('''DELETE FROM auth WHERE account="%s";''' % name)
        db.commit()
        db.close()
        bot.say("User deleted.")

def addKeys(bot, name, info):
    # Setup dbase connection
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()
    
    try:
        c_token, c_secret, a_token, a_secret = info.split(" ")
    except Exception as e:
        bot.say(str(e))
    
    check = c.execute('''SELECT * FROM auth WHERE account="%s";''' % name).fetchall()
    
    if len(check) == 0:
        bot.say("You are not approved to add tokens. Contact Operator873.")
        db.close()
        return
    else:
        try:
            c.execute('''UPDATE auth SET consumer_token="%s", consumer_secret="%s", access_token="%s", access_secret="%s" WHERE account="%s";''' % (c_token, c_secret, a_token, a_secret, name))
            bot.say("Keys added.")
        except Exception as e:
            bot.say(str(e))
        finally:
            db.commit()
            db.close()

def processinfo(info):
    info = "a=" + info
    l = re.split(r"(\w)=", info)[1:]
    
    data = {l[i]: l[i+1] for i in range(0, len(l), 2)}
    
    for key in data:
        data[key] = data[key].strip()
    
    if 'd' in data:
        adjust = re.sub(r"([0-9]+([0-9]+)?)",r" \1 ", data['d'])
        data['d'] = re.sub(' +', ' ', adjust).strip()
    
    return data


@module.commands('testblock')
@module.nickname_commands('testblock')
def commandtestBlock(bot, trigger):
    # New syntax: !block Some Nick Here p=project d=duration r=reason
    
    data = processinfo(trigger.group(2))
    
    if len(data) < 4:
        bot.say("Command missing arguements: !block <target account> p=project d=duration r=reason for block")
        return
    elif data['a'] == '':
        bot.say("Target of block must go first or be indicated with 'a=target account'. !block <target account> p=project d=duration r=reason for block")
        return
    else:
        try:
            project = data['p']
            target = data['a']
            until = data['d']
            reason = data['r']
        except Exception as e:
            bot.say("Error! " + str(e))
            return
        
        bot.say(target + " would be blocked on " + project + " for " + until + " with reason: " + reason)

@module.commands('block')
@module.nickname_commands('block')
def commandBlock(bot, trigger):
    # New syntax: !block Some Nick Here p=project d=duration r=reason
    
    data = processinfo(trigger.group(2))
    
    if len(data) < 4:
        bot.say("Command missing arguements: !block <target account> p=project d=duration r=reason for block")
        return
    elif data['a'] == '':
        bot.say("Target of block must go first or be indicated with 'a=target account'. !block <target account> p=project d=duration r=reason for block")
        return
    else:
        try:
            project = data['p']
            target = data['a']
            until = data['d']
            reason = data['r']
        except Exception as e:
            bot.say("Error! " + str(e))
            return
    
    doBlock(bot, trigger.account, project, target, until, reason)

@module.commands('lta')
@module.nickname_commands('lta')
def commandltablock(bot, trigger):
    # New syntax: !lta Some Nick Here p=project
    
    data = processinfo(trigger.group(2))
    
    if len(data) < 2:
        bot.say("Command missing arguements: !lta Some Nick Here p=project")
        return
    elif data['a'] == '':
        bot.say("Target of block must go first or be indicated with 'a=target account'. !lta Some Nick Here p=project")
        return
    else:
        try:
            project = data['p']
            target = data['a']
        except Exception as e:
            bot.say("Error! " + str(e))
            return
    
    doltaBlock(bot, trigger.account, project, target)

@module.commands('tpa')
@module.nickname_commands('tpa')
def commandRevoketpa(bot, trigger):
    # New syntax: !tpa Some Nick Here p=project d=duration r=reason
    
    data = processinfo(trigger.group(2))
    
    if len(data) < 4:
        bot.say("Command missing arguements: !tpa <target account> p=project d=duration r=reason for block")
        return
    elif data['a'] == '':
        bot.say("Target of block must go first or be indicated with 'a=target account'. !tpa <target account> p=project d=duration r=reason for block")
        return
    else:
        try:
            project = data['p']
            target = data['a']
            until = data['d']
            reason = data['r']
        except Exception as e:
            bot.say("Error! " + str(e))
            return

    dorevokeTPA(bot, trigger.account, project, target, until, reason)

@module.commands('reblock')
@module.nickname_commands('reblock')
def commandreBlock(bot, trigger):
    # New syntax: !reblock Some Nick Here p=project d=duration r=reason
    
    data = processinfo(trigger.group(2))
    
    if len(data) < 4:
        bot.say("Command missing arguements: !reblock <target account> p=project d=duration r=reason for block")
        return
    elif data['a'] == '':
        bot.say("Target of block must go first or be indicated with 'a=target account'. !reblock <target account> p=project d=duration r=reason for block")
        return
    else:
        try:
            project = data['p']
            target = data['a']
            until = data['d']
            reason = data['r']
        except Exception as e:
            bot.say("Error! " + str(e))
            return
    
    doReblock(bot, trigger.account, project, target, until, reason)

@module.commands('proxyblock')
@module.nickname_commands('proxyblock')
def commandproxyBlock(bot, trigger):
    # New syntax: !proxyblock Some Nick Here p=project d=duration
    
    data = processinfo(trigger.group(2))
    
    if len(data) < 3:
        bot.say("Command missing arguements: !proxyblock Some Nick Here p=project d=duration")
        return
    elif data['a'] == '':
        bot.say("Target of block must go first or be indicated with 'a=target account'. !proxyblock Some Nick Here p=project d=duration")
        return
    else:
        try:
            project = data['p']
            target = data['a']
            until = data['d']
        except Exception as e:
            bot.say("Error! " + str(e))
            return
    
    reason = "[[m:NOP|Open proxy]]"
    doReblock(bot, trigger.account, project, target, until, reason)

@module.commands('gblock')
@module.nickname_commands('gblock')
def commandglobalBlock(bot, trigger):
    # New syntax: !gblock Some IP Here d=duration r=reason
    
    data = processinfo(trigger.group(2))
    
    if len(data) < 3:
        bot.say("Command missing arguements: !gblock Some IP Here d=duration r=reason")
        return
    elif data['a'] == '':
        bot.say("Target of block must go first or be indicated with 'a=target account'. !gblock Some IP Here d=duration r=reason")
        return
    else:
        try:
            project = data['p']
            target = data['a']
            until = data['d']
            reason = data['r']
        except Exception as e:
            bot.say("Error! " + str(e))
            return

    if reason == "proxy":
        reason = "[[m:NOP|Open proxy]]"
    elif reason == "LTA" or reason == "lta":
        reason = "Long term abuse"
    elif reason == "spam":
        reason = "Cross wiki spam"
    elif reason == "abuse":
        reason = "Cross wiki abuse"
    else:
        pass
    
    doGlobalblock(bot, trigger.account, target, until, reason)

@module.commands('lock')
@module.nickname_commands('lock')
def commandLock(bot, trigger):
    # New syntax: !lock Some Account r=reason
    
    data = processinfo(trigger.group(2))
    
    if len(data) < 2:
        bot.say("Command missing arguements: !lock Some Account r=reason")
        return
    elif data['a'] == '':
        bot.say("Target of block must go first or be indicated with 'a=target account'. !lock Some Account r=reason")
        return
    else:
        try:
            target = data['a']
            reason = data['r']
        except Exception as e:
            bot.say("Error! " + str(e))
            return

    if reason == "proxy":
        reason = "[[m:NOP|Open proxy]]"
    elif reason == "LTA" or reason == "lta":
        reason = "Long term abuse"
    elif reason == "spam":
        reason = "Cross wiki spam"
    elif reason == "abuse":
        reason = "Cross wiki abuse"
    elif reason == "banned" or reason == "banned user":
        reason = "Globally banned user"
    else:
        pass
    
    doLock(bot, trigger.account, target, reason)

@module.commands('unlock')
@module.nickname_commands('unlock')
def commandUnlock(bot, trigger):
    # !unlock Some Account
    reason = "Unlock"
    doUnlock(bot, trigger.account, trigger.group(2), reason)

@module.commands('softblock')
@module.nickname_commands('softblock')
def commandSoftblock(bot, trigger):
    # New syntax: # !softblock Some Nick Here p=project d=duration r=Some reason here.
    
    data = processinfo(trigger.group(2))
    
    if len(data) < 4:
        bot.say("Command missing arguements: !softblock Some Nick Here p=project d=duration r=Some reason here.")
        return
    elif data['a'] == '':
        bot.say("Target of block must go first or be indicated with 'a=target account'. !softblock Some Nick Here p=project d=duration r=Some reason here.")
        return
    else:
        try:
            project = data['p']
            target = data['a']
            until = data['d']
            reason = data['r']
        except Exception as e:
            bot.say("Error! " + str(e))
            return
    
    doSoftblock(bot, trigger.account, project, target, until, reason)

@module.commands('unblock')
@module.nickname_commands('unblock')
def commandUnblock(bot, trigger):
    # New syntax: !unblock Some Account Here p=project r=reason
    
    data = processinfo(trigger.group(2))
    
    if len(data) < 4:
        bot.say("Command missing arguements: !unblock Some Account Here p=project r=reason")
        return
    elif data['a'] == '':
        bot.say("Target of block must go first or be indicated with 'a=target account'. !unblock Some Account Here p=project r=reason")
        return
    else:
        try:
            project = data['p']
            target = data['a']
            reason = data['r']
        except Exception as e:
            bot.say("Error! " + str(e))
            return
    
    doUnblock(bot, trigger.account, project, target, reason)
    
@module.require_owner(message="This function is only available to Operator873.")
@module.commands('addUser')
@module.nickname_commands('addUser')
def commandAdd(bot, trigger):
    addUser(bot, trigger.group(2))

@module.require_owner(message="This function is only available to Operator873.")
@module.commands('remUser')
@module.nickname_commands('remUser')
def commandRem(bot, trigger):
    remUser(bot, trigger.group(2))

@module.require_privmsg(message="This function must be used in PM.")
@module.commands('tokens')
@module.nickname_commands('tokens')
def commandTokens(bot, trigger):
    addKeys(bot, trigger.account, trigger.group(2))


@module.commands('getapi')
def getAPI(bot, trigger):
    # Setup dbase connection
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()
    wiki = str(trigger.group(3))
    
    check = c.execute('''SELECT apiurl FROM wikis WHERE wiki="%s";''' % wiki).fetchone()
    
    db.close()
    
    if check is not None:
        bot.say(check[0])
    else:
        bot.say("I don't know " + wiki + ". You can add it with !addapi <project> <api url>")

@module.commands('addapi')
def addapi(bot, trigger):
    
    try:
        wiki, apiurl = trigger.group(2).split(' ', 1)
    except:
        bot.say("Malformed command. Syntax is '!addapi <project> <api url>")
        return
    
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()
    
    check = c.execute('''SELECT * FROM wikis WHERE wiki="%s";''' % wiki).fetchone()
    
    if check is not None:
        bot.say("I already know " + wiki + ". The api url is " + check[1])
    else:
        c.execute('''INSERT INTO wikis VALUES("%s", "%s");''' % (wiki, apiurl))
        db.commit()
        bot.say(wiki + " was added with url: " + apiurl)
    
    db.close()

@module.require_owner(message="This function is only available to Operator873.")
@module.commands('delapi')
def delapi(bot, trigger):
    db = sqlite3.connect(SAM_DB)
    c = db.cursor()
    
    check = c.execute('''SELECT * FROM wikis WHERE wiki="%s";''' % trigger.group(3)).fetchone()
    
    if check is None:
        bot.say(trigger.group(3) + " doesn't exist in the database.")
    else:
        c.execute('''DELETE FROM wikis WHERE wiki="%s";''' % trigger.group(3))
        db.commit()
        bot.say(trigger.group(3) + " was removed from the database.")
    
    db.close()

@module.commands('whoami')
def whoami(bot, trigger):
    bot.say("You are " + trigger.nick + " using Freenode account: " + trigger.account + ".")

@module.commands('memadd')
def memadd(bot, trigger):
    response = addtomemory(trigger.account, trigger.group(2))
    if response['status'] == "Success":
        bot.say(response['data'])
    else:
        bot.say("Operator873 something blew up! " + response['data'])

@module.commands('memclear')
def memclear(bot, trigger):
    response = clearmemory(trigger.account)
    
    if response['status'] == "Success":
        bot.say(response['data'])
    else:
        bot.say("Operator873 something blew up! " + response['data'])

@module.commands('memdel')
def memdel(bot, trigger):
    response = delfrommemory(trigger.account, trigger.group(2))
    
    if response['status'] == "Success":
        bot.say(response['data'])
    else:
        bot.say("Operator873 something blew up! " + response['data'])

@module.commands('memshow')
def memshow(bot, trigger):
    payload = getfrommemory(trigger.account)
    
    if payload['status'] == "Success":
        if len(payload['data']) > 0:
            response = ""
            for entry in payload['data']:
                if len(response) > 0:
                    response = response + ", " + entry[0]
                else:
                    response = entry[0]
            bot.say("Items currently in memory: " + response)
        else:
            bot.say("It doesn't appear you have anything stored in memory.")
    else:
        bot.say("An error occured fetching memory items. Ping Operator873")
        bot.say(payload['data'])

@module.commands('memory')
def domemory(bot, trigger):
    try:
        action, info = trigger.group(2).split(" ", 1)
    except:
        bot.say("Missing data. Syntax is !memory <action> <optional args>")
        return
    
    # New syntax: !memory <action> a=account p=project d=duration r=reason
    
    dump = getfrommemory(trigger.account)

    data = processinfo(info)
    
    if len(dump['data']) > 0:
    
        if action.lower() == "lock":
            # !memory lock r=reason
            
            try:
                reason = data['r']
            except:
                bot.say("Malformed command. Syntax is !memory lock r=reason")
                return
            
            if reason.lower() == "proxy":
                reason = "[[m:NOP|Open proxy]]"
            elif reason.lower() == "lta":
                reason = "Long term abuse"
            elif reason.lower() == "spam":
                reason = "Cross wiki spam"
            elif reason.lower() == "abuse":
                reason = "Cross wiki abuse"
            elif reason.lower() == "banned" or reason.lower() == "banned user":
                reason = "Globally banned user"
            else:
                pass
            
            for item in dump['data']:
                doLock(bot, trigger.account, item[0], reason.strip())
            
            devnull = clearmemory(trigger.account)
                
        elif action.lower() == "block":
            # !memory block p=project d=duration r=reason
            
            try:
                reason = data['r']
                until = data['d']
                project = data['p']
            except:
                bot.say("Malformed command. Syntax is !memory block p=project d=duration r=reason")
                return
            
            for item in dump['data']:
                doBlock(bot, trigger.account, project.lower(), item[0], until, reason)
            
            devnull = clearmemory(trigger.account)
                
        elif action.lower() == "lta":
            # !memory lta p=project
            
            try:
                project = data['p']
            except:
                bot.say("Malformed command. Syntax is !memory lta p=project")
                return
            
            for item in dump['data']:
                doltaBlock(bot, trigger.account, project, item[0])
            
            devnull = clearmemory(trigger.account)
        
        elif action.lower() == "gblock":
            # !memory gblock d=duration r=reason
            try:
                project = data['p']
                reason = data['r']
            except:
                bot.say("Malformed command. Syntax is !memory gblock d=duration r=reason")
                return

            if reason.lower() == "proxy":
                reason = "[[m:NOP|Open proxy]]"
            elif reason.lower() == "lta":
                reason = "Long term abuse"
            elif reason.lower() == "spam":
                reason = "Cross wiki spam"
            elif reason.lower() == "abuse":
                reason = "Cross wiki abuse"
            elif reason.lower() == "banned" or reason.lower() == "banned user":
                reason = "Globally banned user"
            else:
                pass
            
            for item in dump['data']:
                doGlobalblock(bot, trigger.account, item[0], until, reason)
            
            devnull = clearmemory(trigger.account)
        
        elif action.lower() == "test":
            # !memory test p=project d=duration r=reason
            try:
                reason = data['r']
                until = data['d']
                project = data['p']
            except:
                bot.say("Malformed command. Syntax is !memory test p=project d=duration r=reason")
                return
            
            for item in dump['data']:
                bot.say(item[0] + " would be blocked on " + project + ". Length: " + until + ". Reason: " + reason)
            
            bot.say("I would clear memory now, but I haven't for testing.")
            
        else:
            bot.say("Error! I currently know lock, block, lta, and gblock. Ping Operator873 if additional command is needed.")
            bot.say("Your stored information has not been altered. Please try again.")
    else:
        bot.say("It doesn't appear I have anything in memory to act on for you.")

@module.commands('!samhelp')
def samhelp(bot, trigger):
    bot.say("Commands are listed at https://github.com/Operator873/SAM")
