#!/usr/bin/env python3
"""
Copyright (c) 2019 Lee Bennett
See the LICENSE file for license rights and limitations (MIT).

This script analyzes an Agentry event.log file.
The main goal is to determine the number of occurances of known error messages.

Key features implemented include:
* When not showing all details, hide any groups with leading underscore in name
* When not showing all details, Hide all output for errors that don't occur.

Current Limitations/future improvment ideas
* 
* Show error descriptions in more user oriented way.
* Show Error detail level
* Report on errors by category, e.g. Locked
* Show # of sub errors and # without more detailed break down.
* Output results to a file
* Command line switches to only consider entries within a specified time period.
* 
* Allow a nesting hierarchy of error messages, e.g. Java exception, with many subtypes
* Associate input files to specific server in a cluster
* Results from different input files are not time sorted in output.
* Implement concurent processing of multiple input files
"""
import sys
import os
import re
import glob
from datetime import datetime, timedelta
#from datetime import timedelta
from collections import deque
#from operator import attrgetter
import statistics
import csv

timestampFormat = '%m/%d/%Y %H:%M:%S'

# Regex used to match relevant loglines 
#Example line: 02/04/2015 12:33:35, 0, 0, 2, Thr 6480, Agentry Startup
#line_regex = re.compile(r"(\d{2}[-/]\d{2}[-/]\d{4}\s+\d{2}:\d{2}:\d{2}),\s*(\d+),\s*(\d+),\s*(\d+),\s*Thr\s*(\d+),\s*(.*)")
#                           Date                       Time             , Type   , Group  , Id     ,        thread, Message


#Command Line switches
showUsers = True
start = None
end = None
onlyFirst = False
eventPatternFile = "EventPatterns.csv"
showDetail = False
typeFilter = None
debug = False

def line_regex():
    return re.compile(r"(\d{2}[-/]\d{2}[-/]\d{4}\s+\d{2}:\d{2}:\d{2}),\s*(\d+),\s*(\d+),\s*(\d+),\s*Thr\s*(\d+),\s*(.*)")

class EventPattern:
    _patterns = []
    def __init__(self, name, regEx, parent):
        self.patternId = (name)
        self.name = name
        self.regEx = re.compile(regEx)

        self.groupNames = []
        self.groupValues = []
        for i in self.regEx.groupindex:
            self.groupNames.append(i)
            self.groupValues.append(set())
        self.parentId = (parent)
        self.events = []
        self.subPatterns = []
        if len(self.parentId) > 0:
            EventPattern.addSubPattern(self)
        else:
            EventPattern._patterns.append(self)

    @staticmethod
    def addSubPattern(pattern):
        ret = False
        for p in EventPattern._patterns:
            if pattern.parentId == p.patternId:
                p.subPatterns.append(pattern)
                ret = True
                break
            else:
                sp = EventPattern.findSubPatternWithId(p, pattern.parentId)
                if sp != None:
                    sp.subPatterns.append(pattern)
                    ret = True
                    break
        return ret

    @staticmethod
    def findSubPatternWithId(pattern, id):
        for p in pattern.subPatterns:
            if p.patternId == id:
                return p
            sp = EventPattern.findSubPatternWithId(p, id)
            if sp != None:
                return sp
        return None
        

        
    @staticmethod
    def loadCsvFile(file):
        with open(file) as csv_file:
            csv_reader = csv.DictReader(csv_file)
            line_count = 0
            for row in csv_reader:
                if debug:
                    print(row)
                EventPattern(row['Name'], row['MessageRegEx'], row['parent'])
                line_count +=1
        
    @staticmethod
    def mainMatchEvent(event):
        ret = None
        if typeFilter != None and event.type != typeFilter:
            return None
        for p in EventPattern._patterns:
            match = p.regEx.match(event.message)
            if not match:
                continue
            if len(p.subPatterns) > 0:
                sp = EventPattern.matchEvent(p, event)
                if sp != None:
                    print
                    return sp
            ret = p
            p.addEvent(event, match)
            break
        return ret

    def matchEvent(self, event):
        ret = None
        match = self.regEx.match(event.message)
        if not match:
            return None
        if len(self.subPatterns) > 0:
            for p in self.subPatterns:
                ret = EventPattern.matchEvent(p, event)
                if ret != None:
                    #print("   "+ p.name)
                    return p
        self.addEvent(event, match)
        return self
    
    def addEvent(self, event, match):
        self.events.append(event)
        for ng in match.groupdict():
            index = self.groupNames.index(ng)
            value = match.group(ng)
            if value == None:
                value = "-None-"
            self.groupValues[index].add(value)
            
    @staticmethod
    def printResults():
        for p in EventPattern._patterns:
            print(p)
            
    def __str__(self):
        occurances = len(self.events)
        if occurances == 0 and not showDetail and len(self.subPatterns) == 0:
            return("")      
        ret = "*** {1:4d}x {0} - {2}\n".format(self.name, occurances, self.regEx.pattern)
        if self.groupNames != None:
            i=0
            for n in self.groupNames:
                if n[0] == '_' and not showDetail:
                    continue
                numValues = len((self.groupValues[i]))
                if numValues > 0:
                    values = ', '.join(self.groupValues[i])
                else:
                    values = ''
                ret +=  "  {0} ({2}): {1}\n".format(n, values, numValues)
                i+=1

        for p in self.subPatterns:
            ret += p.__str__()

        return (ret)
    __repr__ = __str__

class Event:
    """A parsed line from event.log """
#                           Date                       Time             , Type   , Group  , Id     ,        thread, Message

    def __init__(self, match):
##        self.timestamp = match.group(1)
##        if start and self.timestamp < start:
##            raise ValueError('Line pior to start time')
##        if end and self.timestamp > end:
##            raise ValueError('Line after end time')
        self.match = match    #ToDo LRB: Review need to store full match object.
        self.type = int(match.group(2))
        self.group = match.group(3)
        self.id = match.group(4)
        self.thread = match.group(5)
        self.message = match.group(6).strip()

    def __str__(self):
        return ("{0} {1} {2} {2} Thr{3}-{4}".format(self.type, self.group, self.id, self.thread, self.message))
    __repr__ = __str__

class Repo:
    """Repository of all information being analyzed"""

    def __init__(self):
        Repo._initEventPatterns()
        
    def __repr__(self):
        return ""
    __str__ = __repr__

    @staticmethod
    def _initEventPatterns():
        EventPattern.loadCsvFile(eventPatternFile)
                

def mainLoop(files = ['events.log'], users=[]):
    """Main processing loop"""    
    store = Repo();
    lines = 0
    matches = 0
    regex = None
    regex = line_regex()
    for fileName in files:
        if debug:
            print ("********* Processing file {0}\n".format(fileName))
        with open(fileName, "r") as in_file:
            # Loop over each log line
            for line in in_file:
                # If log line matches our regex, print to console, and output file
                lines += 1
                match = regex.match(line)
                if match:
                    matches += 1
                    try:
                        e = Event(match)
                        #print('Match Found: {0}'.format(line))
                    except ValueError:
                        pass
                        print('Matching line skipped: {0}'.format(line))
                    else:
                        EventPattern.mainMatchEvent(e)
    if debug:
        print ('******************** Finished processing all files ***********************************')
        print ("Lines found {0}".format(lines))
        print ("Matches found {0}".format(matches))

    print ("{0}\n".format(store))
    EventPattern.printResults()

def myMain(argv):
    global showUsers, start, end, onlyFirst, eventPatternFile, showDetail, typeFilter, debug
#    if len(argv) < 2:
    if len(argv) < 0:
        print ("Need to provide a space separated list of files (which all include a .) and (optionally) users (which don't include a .)")
        return
    else:
        files = []
        users = []
        for arg in argv[1:]:
            if debug:
                print(arg)
            if start == True:
                start = arg
            elif end == True:
                end = arg
            elif arg == '-debug':
                debug = True    
            elif arg == '-error0':
                typeFilter = 0
            elif arg == '-error1':
                typeFilter = 1
            elif arg == '-onlyFirst':
                onlyFirst = True
            elif arg == '-showDetail':
                showDetail = True    
            elif arg == '-start':
                start = True
            elif arg == '-end':
                end = True
            elif arg.lower().find('.csv') >= 0:
                eventPatternFile = arg.lower()              
            elif arg.find('.') < 0:
                users.append(arg.lower())
            else:
                if arg.find('*') <0:
                    files.append(arg)
                else:
                    files.append(glob.glob(arg))
        if eventPatternFile == None:
            print ("Need to specify an EventPatterns.csv file")
            return
        elif len(files) < 1:
            files.append('events.log')
            mainLoop(files, users)
            #print ("Need to specify at least one event file to process")
            #return
        else:
            if debug:
                print(files)
            mainLoop(files, users)

if __name__ == '__main__':
    myMain(sys.argv)
else:
    mainLoop()
    
