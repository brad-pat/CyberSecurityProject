import datetime, re

f = None
endian = None
op_endian = None

def set_endian(setendian):
    global endian
    global op_endian
    if setendian == b'\xd4\xc3\xb2\xa1':
        endian = 'little'
    else:
        endian = 'big'

def checknameispcap(filename):
    if filename.endswith(".pcap") == True:
        #print("File name: " + filename + " is valid")
        return True
    else:
        print("Error: Invalid file name! Make sure it ends with .pcap")
        return False

def checkpcapfileexists(file):
    try:
        global f
        f = open(file, "rb")
        print("File has been Opened Successfully!") 
        return True
    except:
        print("Error: File Does not Exist or couldn't be found!")
        return False

def convertToHex(bytes_to_convert):
    conv = int.from_bytes(bytes_to_convert, byteorder=endian)
    conv_hex = "{0:x}".format(conv)
    return conv_hex

def get_network_type(net_type):
    if net_type == 0:
        return "NULL"
    elif net_type == 1:
        return "Ethernet"
    elif net_type == 3:
        return "AX25"
    elif net_type == 6:
        return "IEEE802"
    else:
        return "Unknown"

def convmagicnumber(magic):
    if magic == b'\xd4\xc3\xb2\xa1':
        conv = int.from_bytes(magic, byteorder='big')
        conv_hex = "{0:x}".format(conv)
        return conv_hex
    else:
        conv = int.from_bytes(magic, byteorder='little')
        conv_hex = "{0:x}".format(conv)
        return conv_hex

def global_header_information():
    magic = f.read(4)
    set_endian(magic)
    major = convertToHex(f.read(2))
    minor = convertToHex(f.read(2))
    time = f.read(4)
    accstamps = f.read(4)
    snap = convertToHex(f.read(4))
    network = convertToHex(f.read(4))
    network_int = int(network, 16)
    network_str = get_network_type(network_int)
    length = 24
    print("""
            -------------------------------------------
            |                                         |
            |        Global Header Information        |
            |                                         |
            -------------------------------------------
    """)
    print("Length of Global Header: ", length, "Bytes")
    print("Magic Number:", convmagicnumber(magic), "\nEndianness is:", endian.title(), "Endian")
    snapconv = int(snap, 16)
    print("Major Version:", major, "\nMinor Version:", minor)
    print("Snap Length:", snap, "(Hex)", snapconv, "Dec.")
    if snap == "ffff":
        print("\tSnap Length Info: All Packets Captured")
    else:
        print("\tSnap Length Info: Not all Packets Captured")
    print("Data Link Type: ", network_str, " (", network_int, ")", sep='')

###  PART 2  ###      
def formatt(conv):
    conv = int.from_bytes(conv, byteorder=endian)
    return conv
def conMAC(addr):
    conv = ':'.join(format(c, '02x') for c in bytes(addr))
    return conv
def conIP(addr):
    conv = '.'.join(f'{c}' for c in addr)
    return conv
    
def DHCP():
    print("""
            -------------------------------------------
            |                                         |
            |             DHCP Information            |
            |                                         |
            -------------------------------------------
    """)
    f.seek(24)
    time = formatt(f.read(4))
    time1 = datetime.datetime.utcfromtimestamp(time).strftime('%d-%m-%Y %H:%M:%S')
    f.seek(32)
    length = f.read(2)
    f.seek(372)
    name = f.read(9).decode()
    f.seek(66)
    sIP = f.read(4)
    dIP = f.read(4)
    f.seek(40)
    dMAC = f.read(6)
    sMAC = f.read(6)

    print("Epoch Time:",time)
    print("GMT Time:",time1)
    print("Length:",formatt(length))
    print("Source MAC:", conMAC(sMAC))
    print("Destination MAC:", conMAC(dMAC))
    print("Source IP:", conIP(sIP))
    print("Destination IP:", conIP(dIP))
    print("Client Name:", name)

### PART 3 ###
def topFinder():
    print("""
            -------------------------------------------
            |                                         |
            |        Suspected Website Checker        |
            |                                         |
            -------------------------------------------
    """)
    
    for line in f:
        if re.search(b'(.top)', line):
            if re.search(b'(http)',line):
                if re.search(b'(Origin)',line):
                    print("\nA Suspeted Website has been found ending in .top, here is its Origin:")
                    print(line.decode(), '\n')

## STEP 4 ##
maximum = None
def step1():
    count = {"bing":0, "yahoo":0, "baidu":0, "aol":0, "ask":0, "excite":0, "duck_duck_go":0}
    for line in f:
        if re.search(b'(www.bing)', line):
            count["bing"] += 1
        elif re.search(b'(www.yahoo)', line):
            count["yahoo"] += 1
        elif re.search(b'(www.baidu)', line):
            count["baidu"] += 1
        elif re.search(b'(www.aol)', line):
            count["aol"] += 1
        elif re.search(b'(www.ask)', line):
            count["ask"] += 1
        elif re.search(b'(www.excite)', line):
            count["excite"] += 1
        elif re.search(b'(www.duckduckgo)', line):
            count["duck_duck_go"] += 1
    global maximum
    maximum = max(count, key=count.get)
    print(maximum.title())

def step2():
    maxi = maximum.encode('utf-8')
    f.seek(0)
    search_list = []
    for line in f:
        if re.search(b'(www.)' + maxi, line):
            if re.findall(b'/search', line):
                new = line.decode('utf-8')
                result = re.search('q=(.*)&qs', new).group(1)
                test = str(result).split("+")
                for w in test:
                    if w not in search_list:
                        search_list.append(w)
                        print(w.title(), end=' ')

def step3():
    f.seek(0)
    sites = []
    for line in f:
        if re.search(b'(Host:)', line):
            dec = line.decode()
            parts = dec.split(" ")
            site = parts[1]
            if site not in sites:
                sites.append(site)

    f.seek(0)
    site_list = []
    for line in f:
        if re.search(b'(Set-Cookie)', line):
            if re.findall(b'domain=.', line):
                dec = line.decode()
                parts = dec.split(";")
                for p in parts:
                    if "domain=." in p:
                        if p not in site_list:
                            site_list.append(p)
    used = []
    for s in site_list:
        spl = s.split("=")[1]
        for site in sites:
            if spl in site and spl not in used:
                used.append(spl)
                print("Cookie:")
                print("-", spl)
                print("\nHost:")
                print("-", site)
                

def search_engine_information():
    print("""
            -------------------------------------------
            |                                         |
            |        Search Engine Information        |
            |                                         |
            -------------------------------------------
    """)
    print("\nThe Most Common Search Engine is:\n")
    step1()
    print("\nNext, the words that were used in the Search Engine were:\n")
    step2()
    print("\n\nFinally, the URL of the website that was Recommended and Visited is the last of the below, this list consists of all the websites that had Cookies Set (meaning they were visited).")
    print("Also, if the URL before the Visited site is the Search Engine, that means they came from the Search Engine, Thus making it recommended. Here is the List of each:\n")
    step3()

#STEP 5#
def search():
    print("""
            -------------------------------------------
            |                                         |
            |            Search .PCAP File            |
            |                                         |
            -------------------------------------------
    """)
    pcapsearch = input("Enter a what you wish to search for (Note it will return in Bytes):\n")
    pcapsearch_encoded = pcapsearch.encode('utf-8')
    for line in f:
        if re.search(pcapsearch_encoded, line):
            print(line,'\n')

def main_menu():
    print("""
            -------------------------------------------
            |                                         |
            |        Welcome to Cyber Security        |
            |                                         |
            -------------------------------------------
    """)
    print("\n\n\tBy: Brad Patrick, Toby Scrupps, Tim Rice & Josh Birch\n\n")
    filename = input("Firstly, you need to enter the name of the PCAP file wish to search:\n")
    while checknameispcap(filename) != True:
        filename = input("Firstly, you need to enter the name of the PCAP file wish to search:\n")
    while checkpcapfileexists(filename) != True:
        filename = input("Firstly, you need to enter the name of the PCAP file wish to search:\n")
    print("\n\nProgram currently using '" + filename.title() + "'\n")
    magic = set_endian(f.read(4))
    f.seek(0)
    choice = None
    while choice != 0:
        f.seek(0)
        print("-----------------------------------------------------------------------")
        choice = int(input("\nPlease Select from the following options:\n\n0. Exit\n1. Global Header Information\n2. DHCP Frame Information\n3. Find Suspected Website\n4. Search Engine Details\n\nAdditional Option:\n5. Search Lines\n\nOption: ")) #This is meant to be on above line, moving down to screenshot
        if choice == 1:
            global_header_information()
        if choice == 2:
            DHCP()
        if choice == 3:
            topFinder()
        if choice == 4:
            try:
                search_engine_information()
            except:
                print("Error while processing! (Or .PCAP file doesn't have any search engine results)")
        if choice == 5:
            search()
    f.close()
    another = input("Closed Previous File. Would you like to search another? (Y/N)\nOption: ")
    if another.upper() == "Y" or another.upper() == "YES":
        main_menu()
    else:
        print("\nExiting the Program now.. Thank you for using it!\n")
        input("Press Enter To Exit..")

main_menu()
