import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, urldefrag

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):  
    final_links = []

    #If the resp object or its html content is null, immediately return the final_links
    if resp.raw_response is None or resp is None:
        return final_links

    #Creates a BeautifulSoup object named soup using the html content (resp.raw_response.content)
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

    #For every link found from scraping the web page
    for link in soup.find_all('a'):
        
        #Retrieve the 'href' associated with the <a> hyperlink tag, which can include URLs, but
        #we need to check using is_valid()
        potential_URL = link.get('href')

        #Checks if the potential_URL is valid
        if is_valid(potential_URL):

            #If valid, passes it to the final_links list
            final_links.append(potential_URL)
    
    return final_links

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


