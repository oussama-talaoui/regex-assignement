
"""This is a template for for developing the code of Regex exercise
    
    Remember to rename this filename using the following convention:
    
        syslog_analysis_group-<groupNumber>.py
    
    """
# The first thing to do is to import the regexp module into our script
import re
import string #not used yet

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
    match_pattern = re.findall(r'Failed\spassword\sfor\sinvalid\suser\s(?P<user>.*?) ', text_string)
    print(match_pattern)
    for word in match_pattern:
        count = frequency.get(word, 0)
        frequency[word] = count + 1

    frequency_list = frequency.keys()

    for words in frequency_list:
        print('\''+words+'\'', frequency[words])

    # Function body

def exercise2(fileName="./messages_syslog_class.txt"):
    """Compute the distribution of ssh attacks and IP addresses
        
        Keyword arguments:
        fileName -- path + name of file containing ssh system log events
        """

    # Function body

def exercise3(fileName="./messages_syslog_class.txt"):
    """Obtain a Ranking of failed login attempts by source IP
        
        Keyword arguments:
        fileName -- path + name of file containing ssh system log events
        """

    # Function body

def exercise4(fileName="./messages_syslog_class.txt"):
    """Compute the reverse ranking of average period between login attempts (in seconds)
        
        Keyword arguments:
        fileName -- path + name of file containing ssh system log events
        """

    # Function body

exercise1()


