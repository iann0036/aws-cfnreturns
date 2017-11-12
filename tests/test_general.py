from .context import cfnreturns

import unittest


class GeneralTestSuite(unittest.TestCase):
    def test_apikey(self):
        apikeyref = cfnreturns.get_ref({
            'Type': 'AWS::ApiGateway::ApiKey'
        }, "someApiKey", "myStack")
        print(apikeyref)
        assert len(apikeyref) == 10


if __name__ == '__main__':
    unittest.main()