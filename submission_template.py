
"""This is a template for for developing the code of Regex exercise
    
    Remember to rename this filename using the following convention:
    
        syslog_analysis_group-<groupNumber>.py
    
    """
# The first thing to do is to import the regexp module into our script
import re
import datetime
from copy import deepcopy

def exercise1(fileName="messages_syslog_class.txt"):
    """Compute ranking of usernames according to number of login attempts
        
        Keyword arguments:
        fileName -- path + name of file containing ssh system log events
        """

    # Opening the file in read mode
    text = open(fileName, "r")
    frequency = {}
    text_string = text.read()
    failed = re.findall(r'Failed\spassword\sfor\sinvalid\suser\s(?P<user>.*?) ', text_string)
    success = re.findall(r'session\sopened\sfor\suser\s(?P<user>.*?) ', text_string)
    login_attemps = failed + success
    for word in login_attemps:
        count = frequency.get(word, 0)
        frequency[word] = count + 1

    frequency_list = frequency.keys()
    attemps_list = [(words, frequency[words]) for words in frequency_list]
    attemps_list.sort(reverse=True, key=lambda x: x[1])

    return attemps_list

    # Function body

def exercise2(fileName="./messages_syslog_class.txt"):
    """Compute the distribution of ssh attacks and IP addresses
        
        Keyword arguments:
        fileName -- path + name of file containing ssh system log events
        """
    text = open(fileName, "r")
    frequency = {}
    text_string = text.read()
    match_pattern = re.findall(r'Failed\spassword\sfor\sinvalid\suser\s(?P<user>.*?)\sfrom\s(?P<IPaddr>.*?)\s', text_string)
    IPadrs = [x[1] for x in match_pattern]

    for IPadr in IPadrs:
        count = frequency.get(IPadr, 0)
        frequency[IPadr] = count + 1

    frequency_list = frequency.keys()
    frequency_list

    num_of_attacks_by_IP = [frequency[x] for x in frequency.keys()]
    num_of_attacks_by_IP = sorted(num_of_attacks_by_IP)

    max_num_attack = max(num_of_attacks_by_IP)
    #print(num_of_attacks_by_IP)
    hist = {}
    quarter = 0
    for i in range(len(num_of_attacks_by_IP)):
        if(num_of_attacks_by_IP[i] > (quarter+1)*max_num_attack/4):
            quarter += 1
        hist[quarter+1] = hist.get(quarter+1, 0) + 1

    list = [(str((k-1)*max_num_attack/4)+" < x <= " + str(k*max_num_attack/4), v) for k, v in hist.items()]

    return list

def exercise3(fileName="./messages_syslog_class.txt"):
    """Obtain a Ranking of failed login attempts by source IP
        
        Keyword arguments:
        fileName -- path + name of file containing ssh system log events
        """
    
    text = open(fileName, "r")
    frequency = {}
    text_string = text.read()
    match_pattern = re.findall(r'Failed\spassword\sfor\sinvalid\suser\s(?P<user>.*?)\sfrom\s(?P<IPaddr>.*?)\s',
                               text_string)
    IPadrs = [x[1] for x in match_pattern]

    for IPadr in IPadrs:
        count = frequency.get(IPadr, 0)
        frequency[IPadr] = count + 1

    list = [(k, v) for k, v in frequency.items()]
    list.sort(key=lambda x: -x[1])
    # print(list)

    return list

def exercise4(fileName="./messages_syslog_class.txt"):
    """Compute the reverse ranking of average period between login attempts (in seconds)

        Keyword arguments:
        fileName -- path + name of file containing ssh system log events
        """
    # Opening the file in read mode
    login_attempts = {}
    text = open(fileName, "r")
    text_string = text.readlines()
    for row in text_string:
        attempt = re.search('(.*) crowds-ml sshd\[(.*)\]:.*[user|for] (.*) from (.*) port .*', row)
        if attempt != None:
            login_attempts[attempt.group(2)] = (attempt.group(1), attempt.group(3), attempt.group(4))

    print(login_attempts)
    ip_users_attempts = {}
    # trying to initialize the list in order to put the date
    for u in login_attempts:
        ip_users_attempts[login_attempts[u][2]] = []
    for u in login_attempts:
        ip_users_attempts[login_attempts[u][2]].append(
            datetime.datetime.strptime(login_attempts[u][0], '%b %d  %H:%M:%S'))
    ip_users_avg_con = {}
    # Calculating the average of the connexions in seconds
    for u in ip_users_attempts:
        T = [0] * (len(ip_users_attempts[u]) - 1)
        cpt = 0
        avg = 0
        if (len(ip_users_attempts[u]) > 1):
            for i in range(len(ip_users_attempts[u]) - 1):
                T[cpt] = abs((ip_users_attempts[u][i] - ip_users_attempts[u][i + 1])).total_seconds()
                cpt += 1
            avg = sum(T) / len(T)
            ip_users_avg_con[u] = avg
    # deleting users with only one connexion attempt
    ip_users_avg_con_ = deepcopy(ip_users_avg_con)
    for u in ip_users_avg_con_:
        if ip_users_avg_con[u] == 0:
            del ip_users_avg_con[u]
    # sorting the avg connexion of the users by their IP connexion.
    ip_users_avg_con = sorted(ip_users_avg_con.items(), key=lambda kv: kv[1], reverse=False)
    return ip_users_avg_con

print(exercise4())

