import base64
import binascii
import datetime
import psycopg2
import psycopg2.sql
from typing import List
import yaml

PG_ADMIN_USER = "postgres"

POSTGRES_DIR = "/etc/postgres/"
DB_IP_FILE = POSTGRES_DIR + "postgres-ip"
DB_PW_FILE = POSTGRES_DIR + "postgres-password.yaml"

DB_USERS_FILE = "/etc/users/falco-db-users.yaml"
DB_PORT = 5432
USERS_ROTATE = True


def read_db_pw(filepath: str) -> str:
    try:
        with open(file=filepath, mode="r") as stream:
            db_pw = yaml.safe_load(stream)
    except FileNotFoundError:
        print(f"File {filepath} does not exist.")
        exit(1)
    except yaml.YAMLError as exc:
        print("Falco DB password file seems to be corrupted: %s", exc)
        exit(1)

    pw = db_pw.get("password", None)
    if pw is None:
        print("Falco DB password file seems to be corrupted")
        exit(1)
    return pw


def read_db_ip(filepath: str) -> str:
    try:
        with open(file=filepath, mode="r") as stream:
            ip = stream.read()
    except FileNotFoundError:
        print(f"File {filepath} does not exist.")
        exit(1)

    if ip == "":
        print(f"File {filepath} was empty.")
        exit(1)

    return ip


def read_db_users() -> dict:
    try:
        with open(file=DB_USERS_FILE, mode="r") as stream:
            res = stream.read()
            if is_base64(res):
                userdict = yaml.safe_load(base64.b64decode(res)) or {}
            else:
                userdict = yaml.safe_load(res) or {}
    except FileNotFoundError:
        print("Falco DB users file does not exist.")
        exit(1)
    except yaml.YAMLError as exc:
        print("Falco DB users file seems to be corrupted: %s", exc)
        exit(1)
    except binascii.Error:
        print("Can not decode Falco DB users file")
        exit(1)
    return userdict


def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False


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
            seconds=max_age_days  # TODO switch back to days
        ):
            if rotated < oldest:
                oldest = rotated
                incumbent = user.get("name")
    return incumbent


def rotate(filepath: str, username: str, host: str, port: int, pguser: str, pgpw: str):
    pw = read_secret(filepath, username)
    rotate_pw_db(host, port, pguser, pgpw, username, pw)


def rotate_pw_db(
    host: str, port: str, pguser: str, pgpw: str, rotateuser: str, rotatedpw: str
):
    print(f"Roate user {rotateuser}")
    rotate_cmd = psycopg2.sql.SQL(
        "ALTER ROLE {rotateuser} WITH PASSWORD {rotatedpw};"
    ).format(
        rotateuser=psycopg2.sql.Identifier(rotateuser),
        rotatedpw=psycopg2.sql.Literal(rotatedpw),
    )
    # err_str = f"Could not rotate pw for user {rotateuser}"

    connstr = f"host={host} port={port} user={pguser} password={pgpw}"
    execute_db_cmd(connstr, rotate_cmd)


def read_secret(filepath: str, username: str) -> str:
    with open(filepath, "r") as stream:
        try:
            userdict = yaml.safe_load(stream) or {}
        except yaml.YAMLError as exc:
            print(exc)
            exit(1)

        try:
            for user in userdict.get("users"):
                if user["name"] == username:
                    return user["password"]
        except KeyError:
            exit(1)
    exit(1)


def get_current_user() -> dict:
    users = read_users_file(DB_USERS_FILE)

    incumbent = {
        "rotated": datetime.datetime.min.replace(tzinfo=datetime.UTC).isoformat()
    }

    for user in users.get("users", []):
        if datetime.datetime.fromisoformat(
            str(user.get("rotated"))
        ) > datetime.datetime.fromisoformat(str(incumbent.get("rotated"))):
            incumbent = user
    return incumbent


def read_users_file(filepath: str) -> dict:
    with open(filepath, "r") as stream:
        try:
            userdict = yaml.safe_load(stream) or {}
            return userdict
        except yaml.YAMLError as exc:
            print(exc)
            return {}


def execute_db_cmd(connstr: str, cmd: psycopg2.sql.SQL):
    try:
        conn = psycopg2.connect(connstr)
        conn.autocommit = True  # Needed for DB creation
        with conn.cursor() as cur:
            cur.execute(cmd.as_string(conn))
    except psycopg2.errors.DuplicateObject:
        print("User already exists skipping")
    except psycopg2.errors.DuplicateDatabase:
        print("Database already exists skipping")
    except (psycopg2.DatabaseError, Exception) as error:
        print("DB execution failed")
        raise error
    finally:
        conn.close()


def create_schema(host: str, port: int, pguser: str, pgpw: str, users: dict):
    pw_1 = ""
    pw_2 = ""
    for user in users.get("users"):
        if user.get("name") == "gardener_1":
            pw_1 = user.get("password", None)
        if user.get("name") == "gardener_2":
            pw_2 = user.get("password", None)

    if not pw_1:
        print("Password for gardener_1 user not found.")
        return
    elif not pw_2:
        print("Password for gardener_2 user not found.")
        return

    print("Found users in password file")

    connstr = f"host={host} port={port} user={pguser} password={pgpw}"

    print("Start to setup database")
    print("Creating roles")
    create_roles(connstr, users=["gardener_1", "gardener_2"], pws=[pw_1, pw_2])
    print("Creating database")
    create_db(connstr)

    db_connstr = connstr + " dbname=falco"

    print("Creating table")
    create_table(db_connstr)
    print("Creating idices")
    create_index(db_connstr)
    print("Granting permissions")
    grant_permissions(db_connstr)


def create_roles(connstr: str, users: List[str], pws: List[str]):
    for i, user in enumerate(users):
        cmd = psycopg2.sql.SQL("CREATE ROLE {0} LOGIN PASSWORD {1}").format(
            psycopg2.sql.Identifier(user),
            psycopg2.sql.Literal(pws[i]),
        )
        execute_db_cmd(connstr, cmd)


def create_db(connstr: str, db: str = "falco", owner: str = "postgres"):
    cmd = psycopg2.sql.SQL("CREATE DATABASE {db} OWNER {owner}").format(
        db=psycopg2.sql.Identifier(db),
        owner=psycopg2.sql.Identifier(owner),
    )
    execute_db_cmd(connstr, cmd)


def create_table(connstr: str):
    cmd = psycopg2.sql.SQL(
        """
        CREATE TABLE IF NOT EXISTS falco_events (
            id BIGSERIAL PRIMARY KEY,
            landscape varchar(50),
            project varchar(50),
            cluster varchar(50),
            uuid uuid,
            hostname varchar(255),
            time timestamp,
            rule varchar(80),
            priority varchar(30),
            tags varchar(126),
            source varchar(50),
            message varchar(5000),
            output_fields jsonb);
    """
    )
    execute_db_cmd(connstr, cmd)


def create_index(connstr: str):
    cmd = psycopg2.sql.SQL(
        """
        CREATE INDEX IF NOT EXISTS project_index ON falco_events (project);
        CREATE INDEX IF NOT EXISTS cluster_index ON falco_events (cluster);
        CREATE INDEX IF NOT EXISTS uuid_index  ON falco_events (uuid);
        CREATE INDEX IF NOT EXISTS hostname_index ON falco_events (hostname);
        CREATE INDEX IF NOT EXISTS time_index ON falco_events (time);
        CREATE INDEX IF NOT EXISTS rule_index ON falco_events (rule);
        CREATE INDEX IF NOT EXISTS priority_index ON falco_events (priority);
        CREATE INDEX IF NOT EXISTS tags_index ON falco_events (tags);
        CREATE INDEX IF NOT EXISTS source_index ON falco_events (source);
        CREATE INDEX IF NOT EXISTS output_fields ON falco_events (output_fields);
    """
    )
    execute_db_cmd(connstr, cmd)


def grant_permissions(connstr: str):
    cmd = psycopg2.sql.SQL(
        """
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE falco_events TO gardener_1;
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE falco_events TO gardener_2;
        GRANT CONNECT ON DATABASE falco TO gardener_1;
        GRANT CONNECT ON DATABASE falco TO gardener_2;
    """
    )
    execute_db_cmd(connstr, cmd)


def main():
    ip = read_db_ip(DB_IP_FILE)
    pw = read_db_pw(DB_PW_FILE)
    users = read_db_users()

    create_schema(host=ip, port=DB_PORT, pguser=PG_ADMIN_USER, pgpw=pw, users=users)

    user_to_rotate = who_to_rotate(DB_USERS_FILE, max_age_days=1)
    if user_to_rotate:
        rotate(DB_USERS_FILE, user_to_rotate, ip, DB_PORT, PG_ADMIN_USER, pw)


if __name__ == "__main__":
    main()
