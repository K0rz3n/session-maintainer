
#The system will filter the configuration of applications below modules according to the list below. Only applications that pass filtering can enter the queue for session acquisition and update. All applications are given priority to blacklist filtering, and all contents of the blacklist are removed by taking union. Then whitelist filtering is performed. The whitelist will be filtered from the remaining applications after being removed from the blacklist, and all contents of the whitelist are extracted and unified, as the final result.

# ban some modules 
MODULE_BLACK_LIST = {
    "module_black_list":[]
}

# ban some files in modules 
FILE_BLACK_LIST = {
    "file_black_list":[]
}

# ban some classes in files
CLASS_BLACK_LIST = {
    "class_black_list":[]
}

# only allow some modules
MODULE_WHITE_LIST = {
    "module_white_list":[]
}

# only allow some files in modules
FILE_WHITE_LIST = {
    "file_white_list":[]
}

# only allow some classes in files
CLASS_WHITE_LIST = {
    "class_white_list":[]
}


# Global log level settings
LOGGING = {
    "level":"INFO"
}

# Database connection settings
SESSION_DB = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "",
    "password": "",
    "database": "session_maintainer",
    "connect_timeout": 5.0,
    "charset": "utf8mb4"
}

# Configuration for the number of concurrent workers executing tasks.Setting processes to 2 means that two workers will concurrently consume tasks from the queue. In simulate mode, this implies that two Chrome instances will be launched simultaneously to execute tasks.
DRAMATIQ = {
    "global": {
         "max_retries": 0,
         "time_limit_ms": 600_000
    },
    "simulate":{
        "queue_name": "simulate", # The name does not support modification
        "processes":2,
        "threads":1,
        "log-level": "warning"
    },
    "http":{
        "queue_name": "http", # The name does not support modification
        "processes":8,
        "threads":2,
        "log-level": "warning"
    }
}


# The configuration of session checker
# http_timeout: the request timeout for http
# user_agent: The default useragent, if you do not provide
# modes:Four different strategies for checking the effectiveness of sessions stored in the database, allowing only one to be opened at a time
SESSION_CHECKER = {
    "global":{
        "http_timeout": 10.0,            
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
    },
    "modes":{
        "once":     {"open": True},
        "daily":    {"open": False, "daily_time": "22:33"},
        "interval": {"open": False,  "interval_minutes": 15},
        "none":     {"open": False},
    }

}


#Keep the necessary query for sessioncollectionurl matching the rule, and solve the problem of some URLs using query to route gateways.
#The links affected are:
#(1) Before generating the URL used by checker to verify the login state, the URL will be constructed according to this configuration, and the necessary routing parameters will be kept forcibly. Otherwise, all query will be deleted and the parameters obtained in sessionlist will be spliced.
#(2) When generating sessionhash, the URL will be normalized using this configuration and the necessary parameters will be retained. Otherwise, all query will be deleted and then the calculation will be performed.
URL_NORMALIZER =  {
    "rules": [
      {
        "host": "example.com",
        "path": "/login",
        "keep_keys": ["token", "ts"]
      },
      {
        "host": "example.com",
        "path_prefix": "/api/",
        "keep_keys": ["session_id"]
      },
      {
        "host": "another.com",
        "path_regex": "^/v1/resource/[0-9]+$",
        "keep_keys": ["uid", "sig"]
      }
    ]
  }
