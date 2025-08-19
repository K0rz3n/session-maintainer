import re
import requests

class TestRequest(object):

    @classmethod
    def test_method(cls):

        session_collection_url = ""
        session_collection_headers = {}
        session_collection_cookies = {}
        session_collection_data = {}
        res = requests.post(session_collection_url, headers=session_collection_headers, cookies=session_collection_cookies, json=session_collection_data)

        print("Set-Cookie header:", res.headers.get("Set-Cookie"))
        print("Cookies dict:", res.cookies.get_dict())
        print("Text body:", res.text)
    


if __name__ == "__main__":

    TestRequest.test_method()