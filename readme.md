# Unauthenticated Strapi Exploit: CVE-2023-22894

This repository contains a proof of concept (PoC) exploit for CVE-2023-22894, which allows unauthenticated users to leak sensitive information and hijack Strapi administrator accounts by exploiting Strapi's filtering functionality on private fields.

## Overview

This exploit targets Strapi versions <=4.7.1 and demonstrates how an unauthenticated user can leak sensitive information, such as password hashes and reset tokens, by exploiting Strapi's filtering functionality on private fields in API requests. By chaining this exploit with CVE-2023-22621, it's possible to achieve unauthenticated remote code execution on affected Strapi instances.

## Prerequisites

To run this PoC exploit, you will need the following:

-   Python 3.x
-   Requests library for Python (`pip install requests`)

## Usage

1. Clone the repository and navigate to the directory:

```bash
git clone https://github.com/Saboor-Hakimi/CVE-2023-22894
cd CVE-2023-22894
```

2. Run the `dump-authless.py` exploit script with the following arguments:

```bash
python3 dump-authless.py -u <target_url> -e <endpoint> [-d <dump>]
```

3. The following arguments are required for running the `dump-authless.py` script:

-   `-u` or `--url`: The target URL of the vulnerable Strapi instance.
-   `-e` or `--endpoint`: The public endpoint on Strapi which has a relationship with the User.

Additionally, you can use the optional `-d` or `--dump` argument to dump the password reset token:

-   `-d true`: Dump the password reset token.

Example:

```bash
python3 dump-authless.py -u http://example.com -e /api/articles -d true
```

4. If the exploit is successful, the script will output the leaked sensitive information and password reset token for the targeted Strapi administrator account.

## Disclaimer

This PoC exploit is for educational and research purposes only. Unauthorized access to computer systems is illegal and punishable by law. The author of this repository is not responsible for any misuse or damage caused by the provided code.

## Acknowledgements

Special thanks to the original finder of this vulnerability and the creator of the authenticated exploit for their research and contributions to the security community.
