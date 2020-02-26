"""
Group 05:

 Ana Leventić
 Evelien Schumacher
 Oussama Tahiri Alaoui
 Nikolai Saltykov

"""

# The first thing to do is to import the regexp module into our script as well as the needed packages
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
    # Failed attempts
    failed = re.findall(r'Failed\spassword\sfor\sinvalid\suser\s(?P<user>.*?) ', text_string)
    # Successful attempts
    success = re.findall(r'session\sopened\sfor\suser\s(?P<user>.*?) ', text_string)
    login_attemps = failed + success
    for word in login_attemps:
        count = frequency.get(word, 0)
        frequency[word] = count + 1

    frequency_list = frequency.keys()
    attemps_list = [(words, frequency[words]) for words in frequency_list]
    attemps_list.sort(reverse=True, key=lambda x: x[1])

    return attemps_list


def exercise2(fileName="./messages_syslog_class.txt"):
    """Compute the distribution of ssh attacks and IP addresses

        Keyword arguments:
        fileName -- path + name of file containing ssh system log events
        """
    text = open(fileName, "r")
    frequency = {}
    text_string = text.read()
    match_pattern = re.findall(r'Failed\spassword\sfor\sinvalid\suser\s(?P<user>.*?)\sfrom\s(?P<IPaddr>.*?)\s',
                               text_string)
    ips = [x[1] for x in match_pattern]

    for ip in ips:
        count = frequency.get(ip, 0)
        frequency[ip] = count + 1

    frequency_list = frequency.keys()
    frequency_list

    # Number of attacks by ip
    num_of_attacks = [frequency[x] for x in frequency.keys()]
    num_of_attacks = sorted(num_of_attacks)

    max_num_attack = max(num_of_attacks)
    hist = {}
    quarter = 0
    for i in range(len(num_of_attacks)):
        if (num_of_attacks[i] > (quarter + 1) * max_num_attack / 4):
            quarter += 1
        hist[quarter + 1] = hist.get(quarter + 1, 0) + 1

    result = [(str((k - 1) * max_num_attack / 4) + " < x <= " + str(k * max_num_attack / 4), v) for k, v in
              hist.items()]

    return result


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
    ips = [x[1] for x in match_pattern]

    for ip in ips:
        count = frequency.get(ip, 0)
        frequency[ip] = count + 1

    result = [(k, v) for k, v in frequency.items()]
    result.sort(key=lambda x: -x[1])
    # print(list)

    return result


def exercise4(fileName="messages_syslog_class.txt"):
    """Compute the reverse ranking of average period between login attempts (in seconds)

        Keyword arguments:
        fileName -- path + name of file containing ssh system log events
        """
    # Opening the file in read mode
    login_attempts = {}
    ip_attempts = {}
    text = open(fileName, "r")
    text_string = text.readlines()

    for row in text_string:
        match_pattern = re.search(
            r'(?P<date>.*) crowds.* sshd\[(?P<id>.*)\]: Failed password for invalid user .* from (?P<ip>.*?) ', row)
        if match_pattern != None:
            login_attempts[match_pattern.group(2)] = (match_pattern.group(1), match_pattern.group(3))

    # Preparing the attempts date's list
    for attempt in login_attempts:
        ip_attempts[login_attempts[attempt][1]] = []
    for attempt in login_attempts:
        ip_attempts[login_attempts[attempt][1]].append(
            datetime.datetime.strptime(login_attempts[attempt][0], '%b %d  %H:%M:%S'))
    ip_average = {}
    # Calculating the average between each two successive attempts in seconds
    for attempt in ip_attempts:
        average_list = [0] * (len(ip_attempts[attempt]) - 1)
        counter = 0
        if (len(ip_attempts[attempt]) > 1):
            for i in range(len(ip_attempts[attempt]) - 1):
                average_list[counter] = abs((ip_attempts[attempt][i] - ip_attempts[attempt][i + 1])).total_seconds()
                counter += 1
            avg = sum(average_list) / len(average_list)
            ip_average[attempt] = avg
    # We have to eliminate user with one login attempt
    ip_average_clean = deepcopy(ip_average)
    for attempt in ip_average_clean:
        if ip_average[attempt] == 0:
            del ip_average[attempt]
    # Sorting the reverse ranking of average
    ip_average = sorted(ip_average.items(), key=lambda x: x[1], reverse=False)
    return ip_average


print("## Exercice 1:")
print(exercise1())
print("## Exercice 2:")
print(exercise2())
print("## Exercice 3:")
print(exercise3())
print("## Exercice 4:")
print(exercise4())