import string
import random

def gen_chars(num_chars, upper = False):
    ret = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(num_chars))
    if not upper:
        ret = ret.lower()
    
    return ret

def get_ref(stack_name, res_name, res):
    return get_returns(stack_name, res_name, res)['Ref']

def get_returns(stack_name, res_name, res):
    res_type = res['Type']

    if res_type == 'AWS::ApiGateway::Account':
        raise NotImplementedError
    elif res_type == 'AWS::ApiGateway::ApiKey':
        return {
            'Ref': gen_chars(10)
        }
    else:
        raise NotImplementedError
