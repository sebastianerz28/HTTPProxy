import unittest
import HTTPproxy


class MyTestCase(unittest.TestCase):
    def test_basicRequest(self):
        x = HTTPproxy.parseHTTPRequest("GET http://www.google.com/ HTTP/1.0\r\n\r\n")

        self.assertEqual("GET / HTTP/1.0\r\nHost: www.google.com\r\nConnection: close\r\n\r\n",
                         HTTPproxy.buildRequest(x))

    def test_connectionCloseSpecified(self):
        x = HTTPproxy.parseHTTPRequest("GET http://www.google.com/ HTTP/1.0\r\nConnection: close\r\n\r\n")

        self.assertEqual("GET / HTTP/1.0\r\nHost: www.google.com\r\nConnection: close\r\n\r\n",
                         HTTPproxy.buildRequest(x))

    def test_hostSpecified(self):
        x = HTTPproxy.parseHTTPRequest("GET http://www.google.com/ HTTP/1.0\r\nHost: www.google.com\r\n\r\n")
        print(HTTPproxy.buildRequest(x))
        self.assertEqual("GET / HTTP/1.0\r\nConnection: close\r\nHost: www.google.com\r\n\r\n",
                         HTTPproxy.buildRequest(x))

    def test_hostSpecified(self):
        x = HTTPproxy.parseHTTPRequest("GET http://www.google.com/ HTTP/1.0\r\nAccept-Language: en-US; q=0.9\r\n\r\n")
        self.assertEqual("GET / HTTP/1.0\r\nHost: www.google.com\r\nConnection: close\r\nAccept-Language: en-US; q=0.9\r\n\r\n",
                         HTTPproxy.buildRequest(x))


if __name__ == '__main__':
    unittest.main()
