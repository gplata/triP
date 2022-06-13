# triP
A GeoIP lookup utility utilizing ipinfo.io and abuseipdb.com services

usage='triP.py filename(s) [-w outfile] [-t ipinfo-token]'

'-w', '--write', help='Write output to CSV file instead of stdout'

'-t', '--ipinfo-token', help='Specify ipinfo.io API token if you have one'

'-h', '--help', action='help'


The given files are scraped for IPv4 addresses, and the addresses are used
with the ipinfo and AbuseIPdb providers to obtain location and Abuse confidence data in JSON format.
The JSON data is then parsed and appended to the 'results' list.

For personal use and school lessons practices
