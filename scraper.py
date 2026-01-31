import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, urldefrag

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    base_url = url
    # resp.url: the actual url of the page
    actual_url = getattr(resp, "url", None)
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    if resp is None or resp.status != 200:
        return []
    # resp.error: when status is not 200, you can check the error here, if needed.
    error_msg = getattr(resp, "error", None)
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    if resp.raw_response is None:
        return []
    raw_url = getattr(resp.raw_response, "url", None)
    html_bytes = getattr(resp.raw_response, "content", None)
    if not html_bytes:
        return []
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    links = []
    try: 
        soup = BeautifulSoup(html_bytes, "lxml")
    except Exception:
        return []
    for tag in soup.find_all("a", href=True):
        href = tag.get("href")
        if not href:
            continue
        absolute_url = urljoin(base_url, href)
        absolute_url, _ = urldefrag(absolute_url)
        links.append(absolute_url)
    return links

    return list()

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        # Noticable trap patterns discovered when running
        trap_patterns = [
            r".*calendar.*", 
            r".*share.*", 
            r".*ical.*", 
            r".*wp-login.*",
            r".*replytocom.*", # Common WordPress comment trap
            r".*action=.*"      # Catches compose, template, etc.
        ]
        if any(re.match(pattern, url.lower()) for pattern in trap_patterns):
            return False

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise

