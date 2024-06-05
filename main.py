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
    # EXAMPLE: auditor = dauditor('example.com', ['selector1', 'selector2'], 'TXT')
    auditor = dauditor('example.com', ['selector1'], 'TXT')
    print(auditor.audit_dns_records())
    return

if __name__ == "__main__":
    main()