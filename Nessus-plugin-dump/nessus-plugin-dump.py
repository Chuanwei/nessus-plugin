#!/usr/bin/python

'''
Created on May 17, 2013

@author: jr.rombaldo
'''
import lxml.html  # @UnresolvedImport
import threading
import time
import sys, getopt


'''
    Thread to parallelize the execution, improving performance.
'''
class dumpThread (threading.Thread):
    
    def __init__(self, threadID, name, first, last, delay):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.first = first
        self.last = last
        self.delay = delay
        
    def run(self):
        print (self.first)
        print (self.last)
        for x in xrange(self.first, self.last+2):
            NessusPluginsDump.pluginRange(self.first, self.last, self.name)
            print "%s: [%s] -> time: %d" % (self.name, time.ctime(time.time()), x)
#             print "%s - %d" % (self.name, x )
            time.sleep(self.delay)
        print "Exiting " + self.name




'''
    function to interact with the user on console. Get the parameters and start the threads
'''
def main(argv):
    threads = 5
    delay = 0
    first =0
    last = 0

    error = '\n Usage: nessus-plugin-dump.py {plugin specification}  [performance options]'
    error = error + '\n\tPlugin specification'
    error = error + '\n\t\t -f --first \t First nessus plugin'
    error = error + '\n\t\t -l --last \t Last nessus plugin'
    
    error = error + '\n\tPerformance options'
    error = error + '\n\t\t -t --threads \t nusmber of threads'
    error = error + '\n\t\t -d --delay \t delay between connection per thread'
    
    error = error + '\n\tExample:'
    error = error + '\n\t\t nessus-plugin-dump.py -f 10000 -l 20000 -t 10 -d 0 \n'

    
    try:
        opts, args = getopt.getopt(argv,"hd:t:f:l:" ,["thread","delay", "first", "last" ])
    except getopt.GetoptError:
        print error
        sys.exit(2)
        
    for opt, arg in opts:
        if opt == '-h' :
            print error
            sys.exit()
        elif opt in ("-t", "--thread"):
            threads = arg
        elif opt in ("-d", "--delay"):
            delay = arg
        elif opt in ("-l", "--last"):
            last = arg
        elif opt in ("-f", "--first"):
            first = arg

    if first ==0 or last ==0 :
        print error
        sys.exit();

'''
    function to split the equally the plugin range between the threads
'''
def chunkIt(seq, num):
    avg = len(seq) / float(num)
    out = []
    last = 0.0

    while last < len(seq):
        out.append(seq[int(last):int(last + avg)])
        last += avg
    return out    

if __name__ == "__main__":
     for i in (chunkIt(range(100,200),10)):
        ini = i[0]
        end = i[len(i)-1]
        
        dumpThread(ini, "Thread_"+str(ini)+"<->"+str(end), ini, end, 2).start()
    
    
'''
    Class to wrap the nessus plugin information
'''
class NessusPlugin(object):
    
    def __init__(self, sinopsys, desc , see_also, solution, riskFactor, family, plugin, bids, cves):
        self.sinopsys = sinopsys
        self.desc = desc;
        self.see_also = see_also
        self.solution = solution
        self.riskFactor = riskFactor
        self.family = family
        self.plugin = plugin
        self.bids = bids
        self.cves = cves
 
'''
    extract a text from a html page based on a xptah parameter
'''
def getTxt(page, xpath):
    tmp = page.xpath(xpath)
    return tmp[0] if len(tmp) > 0 else ""

'''
    extract a information vector from a html page based on a xptah parameter
'''
def getVect(page, xpath):
    tmp = {};
    i = 0;
    for elmnt in page.xpath(xpath):
        tmp[i] = elmnt
        i += 1
    return tmp;

'''
    extract a text from based on possition (start, end)
'''
def getTextFromPos(text, start, end):
    str = "";  # @ReservedAssignment
    for i in xrange(start + 1, end - 2):
        str += text[i]
    return str
        


'''
    create a connection with nessus page, extract the plugin information, parse it on Plugin object.
'''
def getPlugin (url):
    try:

        '''
        connect with nessus page an get the HTML
        '''
        page = lxml.html.parse(url).getroot()
        
        
        '''
        extract the plugin information peace and verify if exists on the page.
        '''
        found = page.xpath('//section[@class="container"]/text()')
        try:
            f = found.index("\nPlugin not found.")
            print ('Not found  --> ' + str(f))
            return 
        except ValueError, e:
            # Plugin not found, keep going...
            None
        
        
        '''
        extract the plugins information from html page and wrap them on plugin object
        '''
        elemnt = page.xpath('//div[@class="twothirds"]/p/text()')
        
        sinopsys_idx = 0;
        desc_idx = 0;
        see_also_idx = 0
        solution_idx = 0;
        riskFactor_idx = 0;
        
        '''
        capture the low html peace with the plugin attributes
        '''
        res = list(elemnt);
        try:
            sinopsys_idx = res.index("\nSynopsis :")
            desc_idx = res.index("\nDescription :")
            see_also_idx = res.index("\nSee also :")
            solution_idx = res.index("\nSolution :")
            riskFactor_idx = res.index("\nRisk factor :")
    
        except ValueError, e:
            print (e)
            
        lst = list(elemnt)
        lst.remove("\n")
        
        '''
        extract the exact informaiton from the html peace using the position
        '''
        sinopsys = getTextFromPos(lst, sinopsys_idx, desc_idx)
        desc = getTextFromPos(lst, desc_idx, see_also_idx)
        see_also = getTextFromPos(lst, see_also_idx, solution_idx)
        solution = getTextFromPos(lst, solution_idx, riskFactor_idx)
        riskFactor = getTextFromPos(lst, riskFactor_idx, len(lst) + 2)
        
        '''
        extract the exact informaiton from the html peace using XPATH
        '''    
        family = getTxt(page, '//strong[text() ="Family:"]/../text()')
        plugin = getTxt(page, '//strong[text() ="Nessus Plugin ID:"]/../text()')
        bids = getVect(page, '//strong[text() ="Bugtraq ID:"]/../a/text()') 
        cves = getVect(page, '//strong[text() ="CVE ID:"]/../a/text()')
       
       
        '''
           wrap the plugin information into a object
        '''
        plg = NessusPlugin(sinopsys, desc, see_also, solution, riskFactor, family, plugin, bids, cves)
                
        return plg
    except Exception, e:
        print e


'''
    based on a range, start the connections with tennable server
'''
def pluginRange (start, end, name):
    url = "http://www.tenable.com/plugins/index.php?view=single&id="
    for i in xrange(start, end):
        print name + ' -> ' + url + str(i) + '\n'
        plg = getPlugin(url + str(i))



if __name__ == "__main__":
    main(sys.argv[1:])

