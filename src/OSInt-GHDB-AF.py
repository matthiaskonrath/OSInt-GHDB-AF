"""
    Author: Matthias Konrath
    Email:  office@inet-sec.at
    Github: https://github.com/matthiaskonrath/

    Description:
        Open Source Intelligence Google Hacking Database Auto Finder
"""

# Import a library to handle the google requests
from googleapiclient.discovery import build
# Handle the user options
from optparse import OptionParser
# Parse the yaml file
import yaml


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
            sites = site.split()

            search_string += " site:" + sites[0]

            if len(sites) >= 2:
                for item in sites[1:]:
                    search_string += " OR site:" + item
        else:
            search_string = exploit

        # Search the google database
        results = google_search(api_key=api_key, search_term=search_string, cse_id="012156694711735292392:rl7x1k3j0vy", num=10)
        if results:
            print("Exploit: %s" % exploit)
            print("Description: %s" % google_dork_list[exploit])

            for item in results:
                print("(*) %s" % item.get('link'))

            print("")


# Get the user selected options
parser = OptionParser()
parser.add_option("-a", dest="api_key", action="store", default=None, help="google api key (mandatory)")
parser.add_option("-s", dest="site", action="store", default="", help="site (to set multiple leave spaces) (mandatory)")
parser.add_option("-f", dest="filename", help="yaml file containing the exploits (mandatory)", metavar="FILE")
parser.add_option("-t", dest="type", action="store", default="",
                  help=("scan type (mandatory) (all, footholds, sensitive-directories, vulnerable-files, vulnerable-servers,"
                        "error-messages, network-or-vulnerability-data, various-online-devices, web-server-detection,"
                        "files-containing-usernames, files-containing-passwords, sensitive-online-shopping-info)"
                        "files-containing-juicy-info, pages-containing-login-portals, advisories-and-vulnerabilities"))
(options, args) = parser.parse_args()


# Check if the user supplied the needed inputs
if options.api_key and options.site and options.type and options.filename:
    parser.print_help()
    exit(-1)



exploit_data = yaml.load(open(options.filename))

if "footholds" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['foothold'], site=options.site)
if "sensitive-directories" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['sensitive-directories'], site=options.site)
if "vulnerable-files" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['vulnerable-files'], site=options.site)
if "vulnerable-servers" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['vulnerable-servers'], site=options.site)
if "error-messages" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['error-messages'], site=options.site)
if "web-server-detection" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['web-server-detection'], site=options.site)
if "various-online-devices" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['various-online-devices'], site=options.site)
if "files-containing-usernames" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['files-containing-usernames'], site=options.site)
if "files-containing-passwords" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['files-containing-passwords'], site=options.site)
if "sensitive-online-shopping-info" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['sensitive-online-shopping-info'], site=options.site)
if "files-containing-juicy-info" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['files-containing-juicy-info'], site=options.site)
if "pages-containing-login-portals" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['pages-containing-login-portals'], site=options.site)
if "advisories-and-vulnerabilities" in options.type or "all" in options.type:
    google_dork_finder(api_key=options.api_key, google_dork_list=exploit_data['advisories-and-vulnerabilities'], site=options.site)

