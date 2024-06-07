#!/usr/bin/env python3

"""
Functionality to verify that a domain's SPF, DKIM, and DMARC DNS records are present and properly configured.

Author: Jack Tiffany
"""

import argparse
from domain_auditor import dauditor

def main():
    """
    Main function to make a DNS query for the DNS records of the specified domain, then checks to make sure SPF, DKIM, and DMARC are configured.

    Configure the target domain, if DKIM should be checked, and what selector/record type the DKIM uses. SPF and DMARC will be checked by default.
    """
    COMMAND_LINE_MODE = False

    if COMMAND_LINE_MODE:
        parser = argparse.ArgumentParser(
                            prog="DAud",
                            description="Provides tools to audit your domain's security configurations")
        parser.add_argument('domain_name', type=str, help='Domain name to audit. E.g. example.com')
        dkim_group = parser.add_argument_group('dkim_group')
        parser.add_argument('--spf', '-S', action='store_true', help='Audit SPF record')
        dkim_group.add_argument('--dkim', '-K', action='store_true', help='Audit DKIM record')
        dkim_group.add_argument('--dkim_selectors', type=str, default="", help="Comma separated list of DKIM selectors. E.g. 'selector1, selector2'")
        dkim_group.add_argument('--dkim_record-type', type=str, default='TXT', help='The type of record to query for the DKIM record')
        parser.add_argument('--dmarc', '-D', action='store_true', help='Audit DMARC record')
        parser.add_argument('--all', '-A', action='store_true', help='Shorthand to audit SPF, DKIM, and DMARC records')
        parser.add_argument('--csv', type=str, help='Path to CSV of domains to parse and audit')

        args = parser.parse_args()
    else:
        domain = input("Please enter domain name: ")
        selectors_string = input("Please enter comma separated list of DKIM selectors: ")
        dkim_type = input("Please enter record type for DKIM record: ")

    # normalizing input
    selectors = selectors_string.replace(", ", ",").split(",")
    dkim_type = dkim_type.upper()

    # EXAMPLE: auditor = dauditor('example.com', ['selector1', 'selector2'], 'TXT')
    auditor = dauditor(domain, selectors, dkim_type)
    result = auditor.audit_dns_records()
    if result["SPF"][0]:
        print(f"SPF\tVALID\n\t{result['SPF'][1][0]}")
    else:
        print(f"SPF\tINVALID\n\t{result['SPF'][1][0]}")
    if result["DKIM"][0]:
        for dkim in result['DKIM'][1]:
            print(f"DKIM\tVALID\n\t{dkim}")
    else:
        for dkim in result['DKIM'][1]:
            print(f"DKIM\tINVALID\n\t{dkim}")
    if result["DMARC"][0]:
        print(f"DMARC\tVALID\n\t{result['DMARC'][1][0]}")
    else:
        print(f"DMARC\tINVALID\n\t{result['DMARC'][1][0]}")
    return

if __name__ == "__main__":
    main()