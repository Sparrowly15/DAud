#!/usr/bin/env python3

"""
Functionality to verify that a domain's SPF, DKIM, and DMARC DNS records are present and properly configured.

Author: Jack Tiffany
"""

import re
import dns.exception
import dns.resolver
import dns.rdatatype
import base64

class dauditor():

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']
    resolver.port = 53
    spf_record = None
    dkim_records = None  # one domain can have multiple dkim records if they're on different selectors
    dmarc_record = None

    def __init__(self, audit_target: str, dkim_selector: str = '', dkim_record_type: str = "TXT"):
        self.target = audit_target
        self.selector = dkim_selector
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

    def validate_spf(self, spf_record):
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

    def validate_dkim(self, dkim_record):
        if self.dkim_records is None:
            print("ERROR: DKIM record not fetched")
            return False
        elif len(dkim_record) == 0:
            print("ERROR: no DKIM record was found")
            return False
        elif len(dkim_record) >= 2:
            print("ERROR: multiple DKIM records found on the same selector")
            return False
        dkim_record = re.split(' ', dkim_record)
        # still need to validate
        return

    def validate_dmarc(self):
        if self.dmarc_record is None:
            print("ERROR: DMARC record not fetched")
            return False
        elif len(dmarc_record) == 0:
            print("ERROR: no DMARC record was found")
            return False
        elif len(dmarc_record) >= 2:
            print("ERROR: multiple DKIM records found on the same selector")
            return False
        dmarc_record = re.split(' ', dmarc_record)
        # still need to validate
        return

    def fetch_spf(self):
        """
        Makes a request to the DNS server for the SPF record, parses, then returns it as a list.
        An empty list is returned no match is found.

        Returns:
        list: The parsed SPF record(s)
        """
        txt_records = self.resolver.resolve(self.target, 'TXT')
        spf_record = list()
        for answer in txt_records.rrset:
            a = answer.to_text()
            found_spf = re.search(r'^"(v=spf1.+)"$', a)
            if found_spf is not None:
                spf_record.append(found_spf.group(1))
        return spf_record

    def fetch_dkim(self):
        """
        Makes a request to the DNS server for the DKIM record, parses, then returns it as a list.
        An empty list is returned if no selector is provided or no match is found.

        Returns:
        list: The parsed DKIM record(s)
        """
        if len(self.selector) == 0:     # DKIM can only be checked if the selector is provided. Potential to add guesses on default names in the future.
            return []
        dns_record = self.resolver.resolve(self.target, self.dkim_type)
        dkim_record = list()
        for answer in dns_record.rrset:
            a = answer.to_text()
            found_dkim = re.search(r'^"(v=DKIM1.+)"$', a)
            if found_dkim is not None:
                dkim_record.append(found_dkim.group(1))
        return dkim_record

    def fetch_dmarc(self):
        """
        Makes a request to the DNS server for the DMARC record, parses, then returns it as a list.
        An empty list is returned no match is found.

        Returns:
        list: The parsed DMARC record(s)
        """
        dmarc_domain = "_dmarc." + self.target
        txt_records = self.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_record = list()
        for answer in txt_records.rrset:
            a = answer.to_text()
            found_dmarc = re.search(r'^"(v=DMARC1.+)"$', a)
            if found_dmarc is not None:
                dmarc_record.append(found_dmarc.group(1))
        return dmarc_record

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

def main():
    """
    Main function to make a DNS query for the DNS records of the specified domain, then checks to make sure SPF, DKIM, and DMARC are configured.

    Configure the target domain, if DKIM should be checked, and what selector/record type the DKIM uses. SPF and DMARC will be checked by default.
    """
    auditor = dauditor("amazon.com")  # No selector or record type set for this test

    audit_package = {
        "target": audit_target,
        "dkim_selector": dkim_selector,
        "dkim_name": dkim_selector + "_domainkey." + audit_target,
        "dkim_type": dkim_record_type,
        "resolver": resolver
    }

    try:
        results_dict = audit_dns_records(audit_package)
    except dns.exception.DNSException as generic:               # I'll change this from the base class to a series of specific ones to support automatically retrying in a later update.
        print(f"Failed to resolve due to {generic}")

    print(results_dict)
    return 0

if __name__ == "__main__":
    main()