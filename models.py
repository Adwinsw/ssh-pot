from twisted.enterprise import adbapi
from twistar.registry import Registry
from twistar.dbobject import DBObject


class FakeFile(DBObject):
    __instance = None

    TABLENAME = 'fake_files'

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            print "New _instance Generated"
            cls.__instance = super(FakeFile, cls).__new__(cls, *args, **kwargs)
        return cls.__instance
        # id = db.Column(db.Integer, primary_key=True)
        # name = db.Column(db.String(128))
        # parent_id = db.Column(db.Integer, db.ForeignKey("fake_directories.id"))
        # permision = db.Column(db.Integer)

        # permision_types = dict()


class FakeDirectory(DBObject):
    __instance = None
    TABLENAME = 'fake_directories'

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            print "New _instance Generated"
            cls.__instance = super(FakeDirectory, cls).__new__(cls, *args, **kwargs)
        return cls.__instance
        # id = db.Column(db.Integer, primary_key=True)
        # name = db.Column(db.String(128))
        # parent_id = db.Column(db.Integer, db.ForeignKey("fake_directories.id"))
        # permision = db.Column(db.Integer)

        # permision_types = dict()


class SSHFakeUser(DBObject):
    __instance = None
    TABLENAME = "ssh_fake_users"

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            print "New _instance Generated"
            cls.__instance = super(SSHFakeUser, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    # id = Column(Integer, primary_key=True)
    # username = Column(String(64))
    # password = Column(String(64))


class SSHAttacker(DBObject):
    __instance = None
    TABLENAME = "ssh_attackers"

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            print "New _instance Generated"
            cls.__instance = super(SSHAttacker, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    # id = Column(Integer, primary_key=True)
    # ip = Column(String(32))
    # auth_count = Column(Integer)
    # success_auth_count = Column(Integer)
    # command_count = Column(Integer)
    # success_command_count = Column(Integer)
    # last_activity = Column(Integer)
    # is_online = Column(Boolean)


class SSHConnection(DBObject):
    __instance = None
    TABLENAME = "ssh_connections"

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            print "New _instance Generated"
            cls.__instance = super(SSHConnection, cls).__new__(cls, *args, **kwargs)
        return cls.__instance
        # id = db.Column(db.Integer, primary_key=True)
        # attacker_id = db.Column(db.Integer, db.ForeignKey("ssh_attackers.id"))
        # timestamp = db.Column(db.Integer)


class SSHAttackerAuth(DBObject):
    __instance = None
    TABLENAME = "ssh_attacker_auths"

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            print "New _instance Generated"
            cls.__instance = super(SSHAttackerAuth, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    # id = Column(Integer, primary_key=True)
    # attacker_id = Column(Integer, ForeignKey("telnet_attackers.id"))
    # username = Column(String(64))
    # password = Column(String(64))
    # status = Column(Boolean)
    # timestamp = Column(Integer)


class SSHAttackerCommand(DBObject):
    __instance = None
    TABLENAME = "ssh_attacker_commands"

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            print "New _instance Generated"
            cls.__instance = super(SSHAttackerCommand, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    # id = Column(Integer, primary_key=True)
    # attacker_id = Column(Integer, ForeignKey("telnet_attackers.id"))
    # command = Column(String(64))
    # status = Column(Boolean)
    # timestamp = Column(Integer)


# Registry.DBPOOL = adbapi.ConnectionPool('psycopg2', host="127.0.0.1", user="saboney", password="123", database="honeypot")
Registry.DBPOOL = adbapi.ConnectionPool('MySQLdb', host="localhost", user="avapot", port=13306, passwd="123",
                                        db="honeypot", cp_reconnect=True)
