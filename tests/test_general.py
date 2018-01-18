from .context import cfnreturns

import unittest
import pprint


class GeneralTestSuite(unittest.TestCase):
    def test_apikey(self):
        cfnrets = cfnreturns.CfnReturns()
        apikeyref = cfnrets.get_ref({
            'Type': 'AWS::EC2::EIP'
        })
        assert len(apikeyref) > 6


if __name__ == '__main__':
    unittest.main()