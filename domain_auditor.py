import re
import dns.exception
import dns.resolver
import dns.rdatatype
import base64

class dauditor():
    """
    Handles fetching and parsing of SPF, DKIM, and DMARC records

    Attributes:
    spf_record (list): fetched SPF record for the domain
    dkim_records (list): fetched DKIM record(s) for the selector + domain
    dmarc_record (list): fetched DMARC record for the domain
    target (str): subject of the DNS question
    selectors (str): DKIM selector(s) to go with the domain
    dkim_type (str): name of the record

    Methods:
    change_target(new_target, new_dkim_selector, new_dkim_type): change target and associated DKIM variables, then wipe saved records
    fetch_spf(): makes a request to the DNS server and parses out the SPF record
    fetch_dkim(): makes a request to the DNS server and parses out the DKIM record(s)
    fetch_dmarc(): makes a request to the DNS server and parses out the DMARC record
    validate_spf(): validates that the SPF record is configured correctly
    validate_dkim(): validates that the DKIM record is configured correctly
    validate_dmarc(): validates that the DMARC record is configured correctly
    audit_dns_records(): fetches the SPF, DKIM, and DMARC records, then validates each
    """
    _resolver = dns.resolver.Resolver()
    _resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
    _resolver.port = 53
    spf_record = None
    dkim_records = None  # one domain can have multiple dkim records if they're on different selectors
    dmarc_record = None

    def __init__(self, audit_target: str, dkim_selectors: list = [], dkim_record_type: str = "TXT"):
        self.target = audit_target
        self.selectors = dkim_selectors
        self.dkim_type = dkim_record_type  # which record the DKIM is in
    
    def change_target(self, new_target: str, new_dkim_selectors: list = [], new_dkim_type: str = "TXT"):
        """
        Sets new target, selector, and dkim type to 'swap' targets for the object
        """
        self.spf_record = None
        self.dkim_records = None
        self.dmarc_record = None
        self.target = new_target
        self.selectors = new_dkim_selectors
        self.dkim_type = new_dkim_type

    def fetch_spf(self):
        """
        Makes a request to the DNS server for the SPF record, parses, then returns it as a list.
        An empty list is returned if no match is found.

        Returns:
        list: The parsed SPF record(s)
        """
        self.spf_record = list()
        try:
            txt_records = self._resolver.resolve(self.target, 'TXT')
        except dns.exception.DNSException as error:
            print(f"FAILED SPF FETCH FOR {self.target} WITH ERROR {error}")
            return self.spf_record
        for answer in txt_records.rrset:
            a = answer.to_text()
            found_spf = re.search(r'v=spf1.+(?=")', a)
            if found_spf is not None:
                self.spf_record.append(found_spf.group())
        return self.spf_record

    def fetch_dkim(self):
        """
        Makes a request to the DNS server for the DKIM record, parses, then returns it as a list.
        An empty list is returned if no selector is provided or no match is found.

        Returns:
        list: The parsed DKIM record(s)
        """
        if len(self.selectors) == 0:     # DKIM can only be checked if the selector is provided. Potential to add guesses on default names in the future.
            print("ERROR: no DKIM selectors provided")
            return []
        self.dkim_records = list()
        dkim_domain = "._domainkey." + self.target
        for selector in self.selectors:
            query_name = selector + dkim_domain
            try:
                dns_record = self._resolver.resolve(query_name, self.dkim_type)
            except dns.exception.DNSException as error:
                print(f"FAILED DKIM FETCH FOR {query_name} WITH ERROR {error}")
                continue
            for answer in dns_record.rrset:
                a = answer.to_text()
                found_dkim = re.search(r'v=DKIM1.+(?=")', a)
                if found_dkim is not None:
                    self.dkim_records.append(found_dkim.group())
        return self.dkim_records

    def fetch_dmarc(self):
        """
        Makes a request to the DNS server for the DMARC record, parses, then returns it as a list.
        An empty list is returned if no match is found.

        Returns:
        list: The parsed DMARC record(s)
        """
        self.dmarc_record = list()
        dmarc_domain = "_dmarc." + self.target
        try:
            txt_records = self._resolver.resolve(dmarc_domain, 'TXT')
        except dns.exception.DNSException as error:
            print(f"FAILED DMARC FETCH FOR {dmarc_domain} WITH ERROR {error}")
            return self.dmarc_record
        for answer in txt_records.rrset:
            a = answer.to_text()
            found_dmarc = re.search(r'v=DMARC1.+(?=")', a)
            if found_dmarc is not None:
                self.dmarc_record.append(found_dmarc.group())
        if self.dmarc_record[0][0:10] == 'v=DMARC1;"':
            self.dmarc_record[0] = self.dmarc_record[0].replace('" "', ' ')
        return self.dmarc_record

    def validate_spf(self):
        if self.spf_record is None:
            self.fetch_spf()
        if len(self.spf_record) == 0:
            return (False, "ERROR: no SPF record was found")
        elif len(self.spf_record) >= 2:
            return (False, "ERROR: multiple SPF records found")
        # https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.1
        spf_pattern = re.compile(r'^v=spf1((\s[-~+?]?ip4:\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?)|(\s[-~+?]?ip6:[\da-fA-F:]+(/\d{1,2})?)|(\s[-~+?]?a(:([\w-]+\.)+[\w-]+)?)|(\s[-~+?]?mx(:([\w-]+\.)+[\w-]+)?)|(\s[-~+?]?include:([\w-]+\.)+[\w-]+)|(\sredirect=([\w-]+)[\.\w-]+)|(\sexp=([\w-]+)[\.\w-]+)|(\s[-~+?]?exists:[\S]+)|(\s[\w.-]+=[\S]+))*(\s[-~+?]all)')
        valid_spf = re.match(spf_pattern, self.spf_record[0])
        if valid_spf is not None:
            return (True, valid_spf.group())
        return (False, "ERROR: found SPF record was invalid")

    def validate_dkim(self):
        if self.dkim_records is None:
            self.fetch_dkim()
        if len(self.dkim_records) == 0:
            return (False, "ERROR: no DKIM record was found")
        elif len(self.dkim_records) >= 2:
            # need to fix logic for checking that it's 1 to 1 on selectors and records
            return (False, "ERROR: multiple DKIM records found on the same selector")
        # https://datatracker.ietf.org/doc/html/rfc6376/
        dkim_pattern = re.compile(r'^v\s*=\s*DKIM1((\s*;\s*k\s*=\s*[\w:]+)|(\s*;\s*p\s*=\s*[\w+/]+=*)|(\s*;\s*s\s*=\s*([\w:]+|\*))|(\s*;\s*h\s*=\s*[\w:]+)|(\s*;\s*t\s*=\s*[\w]+)|(\s*;\s*n\s*=\s*[\w\s]+))+\s*;?')
        valid_records = list()
        for dkim_record in self.dkim_records:
            valid_dkim = re.match(dkim_pattern, dkim_record)
            if valid_dkim is not None:
                valid_records.append(valid_dkim.group())
        if len(valid_records) > 0:
            return (True, valid_records)
        return (False, "ERROR: found DKIM records were invalid")

    def validate_dmarc(self):
        if self.dmarc_record is None:
            self.fetch_dmarc()
        if len(self.dmarc_record) == 0:
            return (False, "ERROR: no DMARC record was found")
        elif len(self.dmarc_record) >= 2:
            return (False, "ERROR: multiple DKIM records found on the same selector")
        # https://datatracker.ietf.org/doc/html/rfc7489#section-6.4
        dmarc_pattern = re.compile(r"^v\s*=\s*DMARC1\s*;\s*p\s*=\s*(none|quarantine|reject)((\s*;\s*sp\s*=\s*(none|quarantine|reject))|(\s*;\s*rua\s*=\s*([^;]*))|(\s*;\s*ruf\s*=\s*([^;]+))|(\s*;\s*adkim\s*=\s*[rs])|(\s*;\s*aspf\s*=\s*[rs])|(\s*;\s*ri\s*=\s*\d+)|(\s*;\s*fo\s*=\s*[01ds](\s*:\s*[01ds])*)|(\s*;\s*rf\s*=\s*[a-zA-Z]+)|(\s*;\s*pct\s*=\s*[\d]{3}))*")
        valid_dmarc = re.match(dmarc_pattern, self.dmarc_record[0])
        if valid_dmarc is not None:
            return (True, valid_dmarc.group())
        return (False, "ERROR: found DMARC record was invalid")

    def audit_dns_records(self):
        """
        Consolidates the functionality for fetching and checking the SPF and DMARC records, along with the DKIM record if DKIM selector is provided.

        Returns:
        dict: A dict of tuples with the (boolean result of validation, found record) for each record
        """
        fetched_spf_record = self.fetch_spf()
        fetched_dkim_record = self.fetch_dkim()
        fetched_dmarc_record = self.fetch_dmarc()
        
        results = {
            "SPF": (self.validate_spf(), fetched_spf_record),
            "DKIM": (self.validate_dkim(), fetched_dkim_record),
            "DMARC": (self.validate_dmarc(), fetched_dmarc_record)
        }
        return results

