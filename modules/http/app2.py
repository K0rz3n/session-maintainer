# A class represents an app configuration in an environment
class AppHttpProd(object):

    def __init__(self):

        # appname is used to uniquely identify a class in the database and requires global uniqueness.
        self.application_name = ""
        # session_page_name is only used for marking and placeholder
        self.session_page_name = "xxxx"
        # session_page_url is only used for marking and placeholder
        self.session_page_url = "xxxx"
        # API for receiving incoming username and password for http login
        self.session_collection_url = "https://example.com/account/login_passwd"

        # Request method, only supports GET and POST. GET type is None, POST type supports json and form.
        self.session_collection_method = {
            "name": "POST",
            "type":"form"
        }
        self.session_collection_headers =  {}
        self.session_collection_cookies = {}
        self.session_collection_data = {}
        self.session_list = [
            {
                # session_id and session_name are only used for placeholding and marking, 
                # which facilitates subsequent linkage with other systems.
                # Only the int and string type are restricted here.
                "session_id":3,
                "session_name":"key1_name",
                "session_key":"key1",
            },
            {
                "session_id":4,
                "session_name":"key2_name",
                "session_key":"key2",
            }

        ]

        # Used to configure how to check the validity of login status
        # The checker will use various parameters in the session_list stored in the database to 
        # fill/replace the corresponding location of the request packet to check the validity of the session.
        self.session_state_check = {
            "session_check_method_name":"POST",
            "session_check_method_type":"form",
            "session_check_url":"https://example.com/account/user_info",
            "session_check_headers":{},
            "session_check_cookies":{},
            "session_check_body":{},
            "session_check_benchmark":"xxxxx",
            # Plugin class name used to recalculate the signature in the API before initiating a check request. 
            # Currently, only the interface is left, and has not been tested and implemented yet.
            "session_check_resign":None
        }