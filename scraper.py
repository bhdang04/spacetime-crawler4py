import re
from bs4 import BeautifulSoup
from bs4 import Comment
from collections import Counter, defaultdict
from urllib.parse import urlparse, urljoin, urldefrag


# Global State / Analytics
visited = set()
blacklist = set()
url_depths = {}

# --- SimHash ---
SIMHASH_BITS = 64
SIMHASH_THRESHOLD = 0.90
SIMHASHES = []

Common_Words = Counter()
subdomain_pages = defaultdict(set)
Longest_Page = [" ", 0] #A list containing the current longest URL and it's token count.
unique_pages = set()


Stop_Words = {
    "a","an","and","are","as","at","be","but","by","for","from","has","have",
    "he","her","hers","him","his","i","if","in","into","is","it","its","me",
    "my","not","of","on","or","our","ours","she","so","that","the","their",
    "theirs","them","then","there","these","they","this","those","to","us",
    "was","we","were","what","when","where","which","who","why","will","with",
    "you","your","yours"
}

###########
#  HELPER #
###########

def defrag_url(u):
    if not u:
        return None
    u = u.strip()
    u, _frag = urldefrag(u)
    return u

def clean_soup(soup):
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    for tag in soup.find_all():
        if tag.name and ":" in tag.name:
            tag.decompose()

    for tag in soup.find_all("xml"):
            tag.decompose()

    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        c.extract()
    
    return soup



###########
#   CORE  #
###########

def scraper(url, resp):
    curr_depth = url_depths.get(url, 0)
    clean_url = defrag_url(url)

    if clean_url and resp is not None and resp.raw_response is not None:
        status = getattr(resp.raw_response, "status_code", None)
        if status is None or status < 400:
            unique_pages.add(clean_url)
    
    links = extract_next_links(url, resp, curr_depth)
    return [link for link, depth in links if is_valid(link, depth)]

def extract_next_links(url, resp, curr_depth=0):
    final_links = []
    url = defrag_url(url)
    if not url:
        return final_links

    if url in visited or url in blacklist or resp is None or resp.raw_response is None:
        return final_links

    status = getattr(resp.raw_response, "status_code", None)
    if status is not None and status >= 400:
        blacklist.add(url)
        return final_links


    visited.add(url)
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
    soup = clean_soup(soup)

    text = extract_visible_text(soup)
    tokens = tokenize_A1(text)

    if len(tokens) >= 50:
        fingerprint = compute_simhash(tokens)
        for old_fp in SIMHASHES:
            similarity = simhash_similarity(fingerprint, old_fp)
            if similarity >= SIMHASH_THRESHOLD:
                return final_links
        SIMHASHES.append(fingerprint)



    update_common_words_from_soup(soup)
    update_subdomain_count(url)
    update_size(url, soup)

    if len(visited) % 10 == 0:
        write_top_50()
        write_subdomains()
        write_longest_page()
        write_unique_pages()

    for link in soup.find_all('a'):
        href = link.get('href')
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


def is_valid(url, depth=0, max_depth=10):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    if url in visited or url in blacklist:
       return False

    if depth > max_depth:
        return False

    try:
        if not url:
            return False
        
        #Here we create an allow variable.
        allow = False
        #We parse the given url into a parsed object, which contains its domain, path, etc.
        parsed = urlparse(url)
        path = parsed.path.lower()

        # These paths contain large collections of papers/files that cause
        # crawl bias and excessive near-duplicate pages with low link diversity.
        # We exclude them to keep the crawl balanced and finite.
        if "/papers/" in path or "/publications/" in path or "/files/" in path:
            return False
        
        if "/wp-content/" in path:
            return False
        
        if "/~cs224" in path:
            return False
        
        if "/supplement/randomSmiles100k" in path:
            return False

        if "/~eppstein/pix/" in path:
            return False

        if path.startswith("/releases/") and "/src/" in path:
            return False


        if any(query in parsed.query.lower() for query in ["action=", "tribe-bar-date", r".*/page/\d+.*", "idx=", "do="]):
            return False

        valid_domains = set(["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"])
        parsed_domain = parsed.netloc.lower()
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
            r".*grape.*",
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
            r".*/activity.*", # Found in logs returning 608
            r".*/projects.*", # Found in logs returning 608
            r".*/events/.*", #calendar pages usually that aren't "calendar"
        ]
        
        #Checks if any of the trap_patterns strings are located inside of the url.
        #If there are, we return false, and don't crawl.
        if any(re.search(pattern, url.lower()) for pattern in trap_patterns):
            return False

        #Else, if the URL matches any of these invalid formats, we return false 
        elif re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|mpg|ram|m4v|mkv|odt|ods|odp|odc|odg|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|ppsx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$",
            parsed.path.lower()
        ):
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

###########
#ANALYTICS#
###########


def extract_visible_text(soup):
    return soup.get_text(separator=" ", strip=True)


def compute_simhash(tokens):
    V = [0] * SIMHASH_BITS
    freqs = Counter(tokens)
    for word, weight in freqs.items():
        if word in Stop_Words or len(word) <= 2:
            continue
        h = hash(word)
        for i in range(SIMHASH_BITS):
            if (h >> i) & 1:
                V[i] += weight
            else:
                V[i] -= weight
    fingerprint = 0
    for i in range(SIMHASH_BITS):
        if V[i] > 0:
            fingerprint |= (1 << i)

    return fingerprint

def simhash_similarity(h1, h2):
    return (SIMHASH_BITS - (h1 ^ h2).bit_count()) / SIMHASH_BITS


def tokenize_A1(text: str):
    clean_chars = []
    for char in text:
        if (char.isascii() and char.isalnum()) or char.isspace():
            clean_chars.append(char)
        else:
            clean_chars.append(" ")
    clean_string = "".join(clean_chars).lower()
    return clean_string.split()


def update_common_words_from_soup(soup: BeautifulSoup):

    text = soup.get_text(separator=" ")

    if len(text) == 0:
        return
    
    if len(text) > 50000 and (text.count(" ") / len(text)) < 0.01:
        return

    tokens = tokenize_A1(text)

    for t in tokens:
        if t not in Stop_Words and len(t) > 2 and not t[0].isdigit():
            Common_Words[t] += 1


def update_subdomain_count(url):
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if host.endswith("uci.edu"):
        subdomain_pages[host].add(defrag_url(url))


def write_top_50(out_file="top50_words.txt"):
    with open(out_file, "w", encoding="utf-8") as f:
        for w, c in Common_Words.most_common(50):
            f.write(f"{w}, {c}\n")


def write_subdomains(out_file="subdomains.txt"):
    with open(out_file, "w", encoding="utf-8") as f:
        for host, pages in sorted(
            subdomain_pages.items(),
            key=lambda item: len(item[1]),
            reverse=True
        ):
            f.write(f"{host}, {len(pages)}\n")


def update_size(url, soup):
 
    text = soup.get_text(separator=" ")
 
    if len(text) > 50000 and (text.count(" ") / len(text)) < 0.01:
        return
    
    tokens = tokenize_A1(text)
    
    if(len(tokens) >= Longest_Page[1]):
        Longest_Page[0] = url
        Longest_Page[1] = len(tokens)


def write_longest_page(out_file="longest_page.txt"):
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(f"{Longest_Page[0]}, {Longest_Page[1]}\n")


def write_unique_pages(out_file="unique_pages.txt"):
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(str(len(unique_pages)) + "\n")