from .context import cfnreturns

import unittest
import pprint


class GeneralTestSuite(unittest.TestCase):
    def test_apikey(self):
        apikeyref = cfnreturns.get_ref({
            'Type': 'AWS::ApiGateway::ApiKey'
        }, "someApiKey", "myStack")
        assert len(apikeyref) == 10
        pprint.pprint(
            cfnreturns.get_returns({
                'Type': 'AWS::ElasticLoadBalancing::LoadBalancer'
            })
        )


if __name__ == '__main__':
    unittest.main()