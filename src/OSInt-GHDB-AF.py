"""
    Author: Matthias Konrath
    Email:  office@inet-sec.at
    Github: https://github.com/matthiaskonrath/

    Description:
        Open Source Intelligence Google Hacking Database Auto Finder
"""


# TODO: Write an automatic downloader for the GHDB (https://www.exploit-db.com/google-hacking-database)
# TODO: The description of the exploit should contain the link to the GHDB entry
# TODO: Threading to increase the scanning speed


# Import a library to handle the google requests
from googleapiclient.discovery import build
# Handle the user options
from optparse import OptionParser
# Parse the yaml file
import yaml
from bs4 import BeautifulSoup
from urllib.request import urlopen
import pickle


def print_search_type(type):
    """Function to show the user which type of search is conducted right now"""
    print("\n\n\n")
    print("*#" * 30)
    print("<**> Scanning for %s <**>" % type)
    print("*#" * 30)


def find_between(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""


def download_dorks():
    current_url = 'https://www.exploit-db.com/ghdb/2/'
    pickle_file = "exploit_dict.p"
    exploit_dict = {}
    counter = 0

    while True:
        try:
            if counter >= 100:
                break;
            else:
                counter += 1

            page = urlopen(current_url).read()
            soup = BeautifulSoup(page, "html.parser", from_encoding="iso-8859-1")
            web_data = soup.find_all('a')

            print(current_url)

            for item in web_data:
                item = str(item)
                if "Next GHDB" in item:
                    start_text = "<a href=\""
                    stop_text = "\" style"
                    next_url = (item.split(start_text))[1].split(stop_text)[0]

                if "https://www.google.com/search" in item:
                    start_text = '>'
                    stop_text = '</a>'
                    exploit = ((item.split(start_text))[1].split(stop_text)[0])[:-3].strip()

            exploit_dict[exploit] = current_url
            current_url = next_url

            print(exploit)

        except Exception as exc:
            print(exc)
            exit(0)

    pickle.dump(exploit_dict, open(pickle_file, "wb"))
    print(exploit_dict)


def google_search(api_key, search_term, cse_id, **kwargs):
    """Searches in the google database"""
    service = build("customsearch", "v1", developerKey=api_key)
    res = service.cse().list(q=search_term, cx=cse_id, **kwargs).execute()
    if 'items' in res:
        return res['items']
    else:
        return None


def google_dork_finder(api_key, google_dork_list, site=""):
    """Uses google searches to evaluate the target"""
    for exploit in google_dork_list:
        # Check if the search is limited
        if site != "":
            search_string = exploit
            sites = site.split(",")

            search_string += " site:" + sites[0]

            if len(sites) >= 2:
                for item in sites[1:]:
                    search_string += " OR site:" + item
        else:
            search_string = exploit

        # Search the google database
        results = google_search(api_key=api_key,
                                search_term=search_string,
                                cse_id="012156694711735292392:rl7x1k3j0vy",
                                num=10)
        if results:
            print("Exploit: %s" % search_string)
            print("Description: %s" % google_dork_list[exploit])
            print("Info: Maximal 10 entries get shown (-> use the search sting yourself in google)")

            for item in results:
                print("(*) %s" % item.get('link'))

            print("")


# Get the user selected options
parser = OptionParser()
parser.add_option("-a", dest="api_key", action="store", default=None, help="google api key (mandatory)")
parser.add_option("-s", dest="site", action="store", default="", help="site (mandatory) Example: github.com,google.com")
parser.add_option("-f", dest="filename", help="yaml file containing the exploits (mandatory)", metavar="FILE")
parser.add_option("-t", dest="type", action="store", default="",
                  help=("scan type (mandatory) Options: "
                        "all, "
                        "footholds, "
                        "sensitive-directories, "
                        "vulnerable-files, "
                        "vulnerable-servers, "
                        "error-messages, "
                        "network-or-vulnerability-data, "
                        "various-online-devices, "
                        "web-server-detection,"
                        "files-containing-usernames, "
                        "files-containing-passwords, "
                        "sensitive-online-shopping-info, "
                        "files-containing-juicy-info, "
                        "pages-containing-login-portals, "
                        "advisories-and-vulnerabilities"
                        )
                  )
(options, args) = parser.parse_args()


download_dorks()
exit(0)


# Check if the user supplied the needed inputs
if not options.api_key or not options.site or not options.type or not options.filename:
    parser.print_help()
    exit(-1)

exploit_data = yaml.load(open(options.filename))

if "footholds" in options.type or "all" in options.type:
    print_search_type("footholds")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['foothold'],
                       site=options.site)

if "sensitive-directories" in options.type or "all" in options.type:
    print_search_type("sensitive directories")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['sensitive-directories'],
                       site=options.site)

if "vulnerable-files" in options.type or "all" in options.type:
    print_search_type("vulnerable files")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['vulnerable-files'],
                       site=options.site)

if "vulnerable-servers" in options.type or "all" in options.type:
    print_search_type("vulnerable servers")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['vulnerable-servers'],
                       site=options.site)

if "error-messages" in options.type or "all" in options.type:
    print_search_type("error messages")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['error-messages'],
                       site=options.site)

if "web-server-detection" in options.type or "all" in options.type:
    print_search_type("web server detection")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['web-server-detection'],
                       site=options.site)

if "various-online-devices" in options.type or "all" in options.type:
    print_search_type("various online devices")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['various-online-devices'],
                       site=options.site)

if "files-containing-usernames" in options.type or "all" in options.type:
    print_search_type("files containing usernames")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['files-containing-usernames'],
                       site=options.site)

if "files-containing-passwords" in options.type or "all" in options.type:
    print_search_type("files containing passwords")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['files-containing-passwords'],
                       site=options.site)

if "sensitive-online-shopping-info" in options.type or "all" in options.type:
    print_search_type("sensitive online shopping info")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['sensitive-online-shopping-info'],
                       site=options.site)

if "files-containing-juicy-info" in options.type or "all" in options.type:
    print_search_type("files containing juicy info")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['files-containing-juicy-info'],
                       site=options.site)

if "pages-containing-login-portals" in options.type or "all" in options.type:
    print_search_type("pages containing login portals")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['pages-containing-login-portals'],
                       site=options.site)

if "advisories-and-vulnerabilities" in options.type or "all" in options.type:
    print_search_type("advisories and vulnerabilities")
    google_dork_finder(api_key=options.api_key,
                       google_dork_list=exploit_data['advisories-and-vulnerabilities'],
                       site=options.site)