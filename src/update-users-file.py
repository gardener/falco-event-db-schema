#!/usr/bin/env python3

import argparse
import datetime
import secrets
import string
import yaml
from pathlib import Path


USER_1 = "gardener_1"
USER_2 = "gardener_2"

PW_LEN = 40
PW_ROTATION_DAYS = 10


def generate_db_users_file(filepath: str) -> bool:
    try:
        with open(file=filepath, mode="r+") as stream:
            userdict = yaml.safe_load(stream) or {}
    except FileNotFoundError:
        print("Falco DB users file does not exist.")
        userdict = {}
    except yaml.YAMLError as exc:
        print("Falco DB users file seems to be corrupted: %s", exc)
        exit(1)

    # More checks needed?
    if userdict.get("users"):
        print("Nothing to do. Users file exists and has users")
        return False

    create_and_store_user(filepath, USER_1, PW_LEN)
    create_and_store_user(filepath, USER_2, PW_LEN)
    return True


def rotate_db_users_file(filepath: str, rotation_interval: int):
    user_to_rotate = who_to_rotate(filepath, max_age_days=rotation_interval)
    if user_to_rotate:
        rotate_pw_file(filepath, user_to_rotate, PW_LEN)
    else:
        print("No users to rotate")


def rotate_pw_file(filepath: str, username: str, pwlen: int = PW_LEN):
    print(f"Rotating user: {username}")
    pw = gen_password(pwlen)
    store_user(filepath, username, pw)


def who_to_rotate(filepath: str, max_age_days: int) -> str | None:
    with open(filepath, "r") as stream:
        try:
            userdict = yaml.safe_load(stream) or {}
        except yaml.YAMLError as exc:
            print("Can not read users file: %s", exc)
            return None

    if userdict == {} or not userdict.get("users"):
        return None

    oldest = datetime.datetime.max.replace(tzinfo=datetime.UTC)
    incumbent = None
    for user in userdict.get("users"):
        rotated = datetime.datetime.fromisoformat(str(user["rotated"])).replace(
            tzinfo=datetime.UTC
        )
        if rotated < datetime.datetime.now(datetime.UTC) - datetime.timedelta(
            days=max_age_days
        ):
            if rotated < oldest:
                oldest = rotated
                incumbent = user.get("name")
    return incumbent


def create_and_store_user(filepath: str, username: str, pwlen: int):
    if pwlen < 30:
        print("Password length too short")
        exit(1)

    pw = gen_password(pwlen)
    store_user(filepath, username, pw)


def gen_password(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    password = "".join(secrets.choice(alphabet) for i in range(length))
    return password


def store_user(filepath: str, username: str, pw: str):
    try:
        with open(file=filepath, mode="r+") as stream:
            userdict = yaml.safe_load(stream) or {}
    except FileNotFoundError:
        print("Falco DB users file does not exist. Will create.")
        userdict = {}
    except yaml.YAMLError as exc:
        print(exc)
        exit(1)

    outdict = gen_or_alter_user(userdict, username, pw)
    with open(filepath, "w+") as stream:
        yaml.dump(outdict, stream, default_flow_style=False)


def gen_or_alter_user(userdict: dict, username: str, pw: str) -> dict:
    now = datetime.datetime.now(datetime.UTC)
    entry = {"name": username, "password": pw, "rotated": now}

    if userdict.get("users") is None:
        userdict["users"] = [entry]
        return userdict

    users = userdict["users"]
    for i, user in enumerate(users):
        if user.get("name") == username:
            users[i] = entry
            return userdict

    users.append(entry)
    return userdict


def main(filepath, rotation_interval):
    max_rotation = 30
    if rotation_interval > max_rotation:
        print(f"Rotation interval can not be longer than {max_rotation} days")
        exit(1)

    Path(filepath).parent.mkdir(parents=True, exist_ok=True)

    generated = generate_db_users_file(filepath)
    if not generated:
        rotate_db_users_file(filepath, rotation_interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Users file maintenance script")
    parser.add_argument("usersfile", help="path of the users file")
    parser.add_argument(
        "rotation_interval", help="interval for password rotations in days", type=int
    )
    args = parser.parse_args()
    main(args.usersfile, args.rotation_interval)
