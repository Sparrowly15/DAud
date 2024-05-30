import re
import dns.exception
import dns.resolver
import dns.rdatatype
import base64

class dauditor():
    """
    Handles fetching and parsing of SPF, DKIM, and DMARC records

    Attributes:
    resolver (dns.resolver): dnspython resolver object used to make the DNS requests
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
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']
    resolver.port = 53
    spf_record = None
    dkim_records = None  # one domain can have multiple dkim records if they're on different selectors
    dmarc_record = None

    def __init__(self, audit_target: str, dkim_selectors: list = [], dkim_record_type: str = "TXT"):
        self.target = audit_target
        self.selectors = dkim_selectors
        self.dkim_type = dkim_record_type  # which record the DKIM is in
    
    def change_target(self, new_target: str, new_dkim_selector: str = '', new_dkim_type: str = "TXT"):
        """
        Sets new target, selector, and dkim type to 'swap' targets for the object
        """
        self.spf_record = None
        self.dkim_records = None
        self.dmarc_record = None
        self.target = new_target
        self.selector = new_dkim_selector
        self.dkim_type = new_dkim_type

    def fetch_spf(self):
        """
        Makes a request to the DNS server for the SPF record, parses, then returns it as a list.
        An empty list is returned no match is found.

        Returns:
        list: The parsed SPF record(s)
        """
        txt_records = self.resolver.resolve(self.target, 'TXT')
        fetched_spf_record = list()
        for answer in txt_records.rrset:
            a = answer.to_text()
            found_spf = re.search(r'^"(v=spf1.+)"$', a)
            if found_spf is not None:
                fetched_spf_record.append(found_spf.group(1))
        self.spf_record = fetched_spf_record
        return fetched_spf_record

    def fetch_dkim(self):
        """
        Makes a request to the DNS server for the DKIM record, parses, then returns it as a list.
        An empty list is returned if no selector is provided or no match is found.

        Returns:
        list: The parsed DKIM record(s)
        """
        if len(self.selectors) == 0:     # DKIM can only be checked if the selector is provided. Potential to add guesses on default names in the future.
            return []
        dns_record = self.resolver.resolve(self.target, self.dkim_type)
        fetched_dkim_record = list()
        for answer in dns_record.rrset:
            a = answer.to_text()
            found_dkim = re.search(r'^"(v=DKIM1.+)"$', a)
            if found_dkim is not None:
                fetched_dkim_record.append(found_dkim.group(1))
        self.dkim_records = fetched_dkim_record
        return fetched_dkim_record

    def fetch_dmarc(self):
        """
        Makes a request to the DNS server for the DMARC record, parses, then returns it as a list.
        An empty list is returned no match is found.

        Returns:
        list: The parsed DMARC record(s)
        """
        dmarc_domain = "_dmarc." + self.target
        txt_records = self.resolver.resolve(dmarc_domain, 'TXT')
        fetched_dmarc_record = list()
        for answer in txt_records.rrset:
            a = answer.to_text()
            found_dmarc = re.search(r'^"(v=DMARC1.+)"$', a)
            if found_dmarc is not None:
                fetched_dmarc_record.append(found_dmarc.group(1))
        self.dkim_records = fetched_dmarc_record
        return fetched_dmarc_record

    def validate_spf(self):
        if self.spf_record is None:
            print("ERROR: SPF record not fetched")
            return False
        if len(spf_record) == 0:
            print("ERROR: no SPF record was found")
            return False
        elif len(spf_record) >= 2:
            print("ERROR: multiple SPF records found")
            return False
        spf_record = re.split(' ', spf_record)
        # still need to validate
        return

    def validate_dkim(self):
        if self.dkim_records is None:
            print("ERROR: DKIM record not fetched")
            return False
        elif len(self.dkim_records) == 0:
            print("ERROR: no DKIM record was found")
            return False
        elif len(self.dkim_records) >= 2:
            # need to fix logic for checking that it's 1 to 1 on selectors and records
            print("ERROR: multiple DKIM records found on the same selector")
            return False
        split_record = re.split(' ', self.dkim_records)
        # still need to validate
        return

    def validate_dmarc(self):
        if self.dmarc_record is None:
            print("ERROR: DMARC record not fetched")
            return False
        elif len(self.dmarc_record) == 0:
            print("ERROR: no DMARC record was found")
            return False
        elif len(self.dmarc_record) >= 2:
            print("ERROR: multiple DKIM records found on the same selector")
            return False
        split_record = re.split(' ', self.dmarc_record)
        # still need to validate
        return

    def audit_dns_records():
        """
        Consolidates the functionality for fetching and checking the SPF and DMARC records, along with the DKIM record if DKIM selector is provided.

        Parameters
        audit_package (dict): The example string provided

        Returns:
        dict: The result for SPF, DKIM, and DMARC
        """
        spf_record = fetch_spf(audit_package)
        dmarc_record = fetch_dmarc(audit_package)
        dkim_record = fetch_dkim(audit_package)
        
        results = {
            "SPF_valid": validate_spf(spf_record),
            "DKIM_valid": validate_dkim(dkim_record),
            "DMARC_valid": validate_dmarc(dmarc_record)
        }
        return results

