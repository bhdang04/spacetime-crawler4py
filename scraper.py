import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, urldefrag

visited = set() # URLs we have successfully processed
blacklist = set() #URLs we decided traps/ bad content
url_depths = {}

def scraper(url, resp):
    curr_depth = url_depths.get(url, 0)
    links = extract_next_links(url, resp, curr_depth)
    return [link for link, depth in links if is_valid(link, depth)]

def extract_next_links(url, resp, curr_depth=0):
    final_links = []

    #Remove URL fragments so uniqueness stays #'s
    url = defrag_url(url)
    if not url:
        return final_links

    #If we've seen or rejected URL why process it?
    if url in visited or url in blacklist or resp is None or resp.raw_response is None:
        blacklist.add(url)
        return final_links

    #Only treat 4xx/5xx or more pages as bad pages
    status = getattr(resp.raw_response, "status_code", None)
    if status is not None and status >= 400:
        blacklist.add(url)
        print(status)
        return final_links

    #Examine the current page path for known trap sections
    parsed_page = urlparse(url)
    path_lower = (parsed_page.path or "").lower()

    #These folders contain large collection of files not useful
    if "/files/" in path_lower or "/papers/" in path_lower or "/publications/" in path_lower:
        blacklist.add(url)
        return final_links

    #WordPress upload directory = binary files
    if "/wp-content/" in path_lower:
        blacklist.add(url)
        return final_links
    
    #This is the point where a page is considered safe to process
    visited.add(url)

    #Creates a BeautifulSoup object named soup using the html content (resp.raw_response.content)
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

    #For every link found from scraping the web page
    for link in soup.find_all('a'):
        
        #Retrieve the 'href' associated with the <a> hyperlink tag, which can include URLs, but
        #we need to check using is_valid()
        href = link.get('href')

        #Checks if the potential_URL is valid
        if not href:
            continue

        #This block catches URLs that have correct href input types (ie. contain a hyperlink), but 
        #don't lead to a valid IP or destination / aren't in the right format.
        try:
            absolute = urljoin(url,href)
            absolute = defrag_url(absolute)
            
            if not absolute or absolute in visited or absolute in blacklist:
                continue

            new_depth = curr_depth + 1

            if is_valid(absolute, new_depth):
                url_depths[absolute] = new_depth
                final_links.append((absolute, new_depth))
        except ValueError:
            continue
        
    return final_links

def defrag_url(u):
    if not u:
        return None
    u = u.strip()
    u, _frag = urldefrag(u)
    return u

def is_valid(url, depth=0, max_depth=10):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.

    # Implemented a Depth Checker for unique links
    if depth > max_depth:
        return False
    
    #What this does so far is it checks whether the URL passed through the parameter is valid or not.
    try:
        #if no url is passed, return false.
        if not url:
            return False
        
        #Here we create an allow variable.
        allow = False

        #We parse the given url into a parsed object, which contains its domain, path, etc.
        parsed = urlparse(url)

        #If the parsed object contains a query component, mark the URL as invalid.
        #This is because query pages often lead to traps, due to generating an infinite amount of URLs.
        if parsed.query:
            return False

        #A set containing all the valid domains we can crawl for this assignment.
        valid_domains = set(["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"])

        #Returns a lowercased version of the domain from url.
        parsed_domain = parsed.netloc.lower()

        #If the scheme of the potential URL isn't an http or https, we return false.
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        #For every domain in the valid domains list, if the domain from parsed
        #ends with a valid domain name, we set allow to true and break the loop.
        #This means that the URL is valid and we're allowed to crawl it.
        for domain in valid_domains:
            if parsed_domain == domain or parsed_domain.endswith("." + domain):
                allow = True
                break
        
        #If allow ends up turning false, we reject the URL
        if not allow:
                return False

        # Noticable trap patterns discovered when running.
        #trap_patterns contains a list of regex strings which will be used later on to 
        #check if the URL is a trap.
        #For example, a calendar is likely to be indicated by the date format "\d{4}-\d{2}-\d{2}"
        #where d represents digits and {} contains the number of digits. 
        trap_patterns = [
            r".*calendar.*",
            r".*/\d{4}-\d{2}-\d{2}.*",
            r".*/\d{4}-\d{2}.*",
            r".*tribe-bar-date.*",
            r".*share.*", 
            r".*ical.*", 
            r".*/page/\d+.*", #Catches URLs that have multiple pages that the crawler gets stuck in. \d represents any digit 0-9.
            r".*/tree/.*", #Catches git trees that trap crawler.
            r".*/commits?/.*", #Catches git commits.
            r".*/branch(?:es)?/.*", #Catches git branches and branch URLs.
            r".*wp-login.*",
            r".*replytocom.*", # Common WordPress comment trap
            r".*action=.*",      # Catches compose, template, etc.
            r".*[\?&;]c=[dnsm].*[\?&;]o=[ad].*", #catches C=D;O=A ?C=N; O=D
            r".*/author/.*/page/\d+.*", #Ends the WICS crawler trap
            r".*/login.*", #Get rid of login pages
            r".*/activity.*" # Found in logs returning 608
            r".*/projects.*" # Found in logs returning 608
        ]
        
        #Checks if any of the trap_patterns strings are located inside of the url.
        #If there are, we return false, and don't crawl.
        if any(re.search(pattern, url.lower()) for pattern in trap_patterns):
            return False

        #Else, if the URL matches any of these invalid formats, we return false 
        elif re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()):
               return False
        
        #If the length of the URL is larger than 300, the URL is invalid.
        if len(url) > 300:
            return False
        
        #If the URL contains more than 10 "&", we return false.
        if url.count("&") > 10:
            return False
        
        #Otherwise, this means that the URL passed all the tests, and is valid.
        return True
    
    except TypeError:
        print ("TypeError for ", parsed)
        raise