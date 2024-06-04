#!/usr/bin/env python3

"""
Functionality to verify that a domain's SPF, DKIM, and DMARC DNS records are present and properly configured.

Author: Jack Tiffany
"""

from domain_auditor import dauditor

def main():
    """
    Main function to make a DNS query for the DNS records of the specified domain, then checks to make sure SPF, DKIM, and DMARC are configured.

    Configure the target domain, if DKIM should be checked, and what selector/record type the DKIM uses. SPF and DMARC will be checked by default.
    """
    # auditor = dauditor("amazon.com", ["selector1", "selector2"], "CNAME")
    auditor = dauditor("amazon.com")  # No selector or record type set for this test
    auditor.validate_spf()
    exit()
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