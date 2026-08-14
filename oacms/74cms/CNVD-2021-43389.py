#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE POC - 74CMS

CVE ID:        CNVD-2021-43389
Vulnerability: SQL injection in deliver.inc.php
Product:       74CMS
CVSS:          8.8 (HIGH)
Vector:        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

Description:
74CMS (Qishi CMS) deliver.inc.php has a SQL injection vulnerability. Attackers can extract admin hashes and database content via UNION injection. Widely found in Chinese recruitment portals.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2021-43389
"""
import requests

TARGET = ""
