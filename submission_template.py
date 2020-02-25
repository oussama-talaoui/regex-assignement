"""This is a template for for developing the code of Regex exercise

    Remember to rename this filename using the following convention:

        syslog_analysis_group-<groupNumber>.py

    """
# The first thing to do is to import the regexp module into our script
import re
import string  # not used yet


def exercise1(fileName="messages_syslog_class.txt"):
    """Compute ranking of usernames according to number of login attempts

        Keyword arguments:
        fileName -- path + name of file containing ssh system log events
        """
    # TODO: use fileName
    #   get the text file from a relative path that can run everywhere
    # Opening the file in read mode
    text = open("messages_syslog_class.txt", "r")
    frequency = {}
    text_string = text.read()
    failed = re.findall(r'Failed\spassword\sfor\sinvalid\suser\s(?P<user>.*?) ', text_string)
    success = re.findall(r'session\sopened\sfor\suser\s(?P<user>.*?) ', text_string)
    loging_attemps = failed + success
    for word in loging_attemps:
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
    text = open("messages_syslog_class.txt", "r")
    frequency = {}
    text_string = text.read()
    match_pattern = re.findall(r'Failed\spassword\sfor\sinvalid\suser\s(?P<user>.*?)\sfrom\s(?P<IPaddr>.*?)\s',
                               text_string)
    IPadrs = [x[1] for x in match_pattern]

    for IPadr in IPadrs:
        count = frequency.get(IPadr, 0)
        frequency[IPadr] = count + 1

    frequency_list = frequency.keys()
    frequency_list

    num_of_attacks_by_IP = [frequency[x] for x in frequency.keys()]
    num_of_attacks_by_IP = sorted(num_of_attacks_by_IP)

    max_num_attack = max(num_of_attacks_by_IP)
    # print(num_of_attacks_by_IP)
    hist = {}
    quarter = 0
    for i in range(len(num_of_attacks_by_IP)):
        if (num_of_attacks_by_IP[i] > (quarter + 1) * max_num_attack / 4):
            quarter += 1
        hist[quarter + 1] = hist.get(quarter + 1, 0) + 1

    # print(hist)

    list = [(str((k - 1) * max_num_attack / 4) + " < x <= " + str(k * max_num_attack / 4), v) for k, v in hist.items()]
    # print(list)

    return list


def exercise3(fileName="./messages_syslog_class.txt"):
    """Obtain a Ranking of failed login attempts by source IP

        Keyword arguments:
        fileName -- path + name of file containing ssh system log events
        """

    text = open("messages_syslog_class.txt", "r")
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

    # Function body


print(exercise3())