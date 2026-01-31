import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def scraper(url, resp):
    links = extract_next_links(url, resp)
    
    #From the list links, keep onyl the ones where is_valid() is true
    return [link for link in links if is_valid(link)]


#Is meant to take in a URL and a response from the server (in this case, a web page).
#This response will then have all of their hyperlinks extracted and returned as a list.
def extract_next_links(url, resp):
    
    #Note: if resp.status != 200
    #if resp.status == 603, 607 (toob ig)

    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
    final_links = ()

    #For every link found from scraping the web page
    for link in soup.find_all('a'):
        
        #Retrieve the 'href' associated with the <a> hyperlink tag, which can include URLs, but
        #we need to check using is_valid()
        potential_URL = link.get('href')

        #Checks if the potential_URL is valid
        if is_valid(potential_URL):

            #If valid, passes it to the final_links list
            final_links.append(potential_URL)
    
    
    
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content



    return list()

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    # Test
    #have to make sure that only uci domains are allowed
    
    try:
        #Parses the url given to the function, breaking the given URL into
        #small pieces.
        parsed = urlparse(url)

        #A set containing all the valid domains we can crawl for this assignment.
        valid_domains = set(["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"])

        #Returns a lowercased version of the domain from url.
        parsed_domain = parsed.netloc.lower()

        #If the scheme of the potential URL isn't an http or https, we return false.
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        #For every domain in the valid domains list, if the domain from parsed
        #ends with a valid domain name, we set allow to true and break the loop.
        for domain in valid_domains:
            if parsed_domain.endswith(domain):
                allow = True
                break
        
        #If allow is not true (ie. the parsed_domain does not end with a valid domain), we return false
        if not allow:
            return False   
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

        return True
    
    except TypeError:
        print ("TypeError for ", parsed)
        raise
