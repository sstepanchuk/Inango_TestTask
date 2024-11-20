import random
import time
import dns.message
import dns.query
import dns.rdatatype
import concurrent.futures
import sys
import binascii

# DNS Server details
PROXY_SERVER = '192.168.225.88'  # Replace with your DNS proxy server IP
PROXY_PORT = 8000                # Replace with your DNS proxy server port
PUBLIC_DNS_SERVER = '8.8.8.8'    # Google DNS server IP
DNS_PORT = 53                    # Default DNS port for public server

# Test parameters
NUM_REQUESTS = 1000              # Total number of requests for the test
CONCURRENT_REQUESTS = 50         # Number of concurrent threads
TIMEOUT = 2.0                    # Socket timeout in seconds
MAX_DIFFERENCE_THRESHOLD = 0.1   # Maximum allowable average response time difference in seconds

# List of random domains and record types for testing
# List of random domains and record types for testing
DOMAINS = [
    "example.com", "openai.com", "google.com", "github.com", "wikipedia.org",
    "stackoverflow.com", "apple.com", "microsoft.com", "cloudflare.com", "bbc.co.uk",
    "yahoo.com", "bing.com", "amazon.com", "netflix.com", "adobe.com",
    "paypal.com", "spotify.com", "twitter.com", "zoom.us", "dropbox.com",
    "nasa.gov", "who.int", "cdc.gov", "nytimes.com", "forbes.com",
    "cnn.com", "foxnews.com", "huffpost.com", "aljazeera.com", "reuters.com",
    "baidu.com", "yandex.ru", "vk.com", "naver.com", "rakuten.co.jp",
    "samsung.com", "hyundai.com", "lg.com", "ikea.com", "honda.com",
    "toyota.com", "bmw.com", "mercedes-benz.com", "tesla.com", "ford.com",
    "un.org", "gov.uk", "europa.eu", "weforum.org", "whois.net",
    "githubusercontent.com", "medium.com", "wordpress.org", "tumblr.com", "pinterest.com",
    "imgur.com", "flickr.com", "linkedin.com", "indeed.com", "tripadvisor.com"
]

'''
DOMAINS = [
    "paypal.com"
]
'''

RECORD_TYPES = [
    dns.rdatatype.A,          # IPv4 Address
    dns.rdatatype.AAAA,       # IPv6 Address
    dns.rdatatype.MX,         # Mail Exchange
    dns.rdatatype.TXT,        # Text
    dns.rdatatype.CNAME,      # Canonical Name
    dns.rdatatype.SOA,        # Start of Authority
    dns.rdatatype.NS,         # Name Server
    dns.rdatatype.SRV,        # Service Locator
    dns.rdatatype.PTR,        # Pointer (often used in reverse DNS lookups)
    dns.rdatatype.ANY,        # Any Record Type (wildcard query)
]

'''RECORD_TYPES = [dns.rdatatype.NS]'''
RECORD_TYPES = [dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.MX, dns.rdatatype.TXT]

def generate_dns_queries(num_requests):
    """Generate a list of randomized DNS queries."""
    queries = []
    for _ in range(num_requests):
        domain = random.choice(DOMAINS)
        record_type = random.choice(RECORD_TYPES)
        query = dns.message.make_query(domain, record_type, use_edns=False)
        queries.append((domain, record_type, query))
    return queries

def validate_dns_response(response, domain, record_type):
    """Validate that the response contains the expected record type and domain."""
    for answer in response.answer:
        if answer.rdtype == record_type and domain in str(answer):
            return True
    return False

def send_dns_request(query_data, server, port):
    """Send a DNS query to a specified server and measure response time."""
    domain, record_type, query = query_data
    start_time = time.time()
    
    try:
        response = dns.query.udp(query, server, timeout=TIMEOUT, port=port)
        response_time = time.time() - start_time
        
        return response_time, None
    except Exception as e:
        # Handle error by printing the raw packet
        '''try:
            print("\n--- Human-readable DNS Request ---")
            print(f"Error occurred with query: {query}")
            print(f"Error: {e}")
            print("\n--- Hexadecimal Representation ---")
            hex_data = binascii.hexlify(query.to_wire())
            print(" ".join([hex_data[i:i+32].decode() for i in range(0, len(hex_data), 32)]))
        except Exception as inner_e:
            print(f"Error printing query in hex: {inner_e}")
        '''
        return None, str(e)

def run_test(server, port, queries):
    """Run test on a specified DNS server and return statistics."""
    response_times = []
    success_count = 0
    error_count = 0
    errors = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_REQUESTS) as executor:
        futures = [executor.submit(send_dns_request, query_data, server, port) for query_data in queries]
        
        for future in concurrent.futures.as_completed(futures):
            response_time, error = future.result()
            if response_time is not None:
                response_times.append(response_time)
                success_count += 1
            else:
                error_count += 1
                errors[error] = errors.get(error, 0) + 1

    avg_response_time = sum(response_times) / len(response_times) if response_times else 0
    return {
        "avg_response_time": avg_response_time,
        "min_response_time": min(response_times, default=0),
        "max_response_time": max(response_times, default=0),
        "success_count": success_count,
        "error_count": error_count,
        "errors": errors
    }

def compare_results(proxy_results, public_results):
    """Compare results from proxy and public DNS server and output statistics."""
    print("Proxy DNS Server Results:")
    print(f"Average Response Time: {proxy_results['avg_response_time']:.4f} seconds")
    print(f"Min Response Time: {proxy_results['min_response_time']:.4f} seconds")
    print(f"Max Response Time: {proxy_results['max_response_time']:.4f} seconds")
    print(f"Successful Responses: {proxy_results['success_count']}")
    print(f"Failed Responses: {proxy_results['error_count']}")
    print("\nError Distribution for Proxy Server:")
    for error, count in proxy_results["errors"].items():
        print(f"{error}: {count} occurrences")

    print("\nPublic DNS Server Results (8.8.8.8):")
    print(f"Average Response Time: {public_results['avg_response_time']:.4f} seconds")
    print(f"Min Response Time: {public_results['min_response_time']:.4f} seconds")
    print(f"Max Response Time: {public_results['max_response_time']:.4f} seconds")
    print(f"Successful Responses: {public_results['success_count']}")
    print(f"Failed Responses: {public_results['error_count']}")
    print("\nError Distribution for Public DNS Server:")
    for error, count in public_results["errors"].items():
        print(f"{error}: {count} occurrences")

    # Calculate difference in average response times
    response_time_difference = abs(proxy_results["avg_response_time"] - public_results["avg_response_time"])
    print(f"\nAverage Response Time Difference: {response_time_difference:.4f} seconds")
    
    # Return non-zero result if the difference exceeds threshold
    if response_time_difference > MAX_DIFFERENCE_THRESHOLD:
        print(f"\nWarning: Average response time difference ({response_time_difference:.4f} seconds) "
              f"exceeds threshold of {MAX_DIFFERENCE_THRESHOLD} seconds.")
        sys.exit(1)  # Exiting with 1 to indicate significant difference
    else:
        print("\nAverage response time difference is within acceptable limits.")
        sys.exit(0)  # Exiting with 0 to indicate acceptable difference

# Run the test
if __name__ == "__main__":
    print("Generating queries...")
    queries = generate_dns_queries(NUM_REQUESTS)
    
    print("Running test on Proxy DNS Server...")
    proxy_results = run_test(PROXY_SERVER, PROXY_PORT, queries)
    
    time.sleep(5)

    print("\nRunning test on Public DNS Server...")
    public_results = run_test(PUBLIC_DNS_SERVER, DNS_PORT, queries)
    
    # Compare results
    compare_results(proxy_results, public_results)