# -*- coding: utf-8 -*-
import base64
import json
import re
import time
import logging

import rsa
from requests import Session
from requests import Request
from urllib import unquote

from yunpan_helper.exceptions import GetShareListFailed

logger = logging.getLogger(__name__)


class BaiduShareCrawler(object):
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, sdch',
            'Accept-Language': 'zh-CN,zh;q=0.8',
            'Connection': 'keep-alive',
            'Host': 'passport.baidu.com',
            'Referer': 'http://pan.baidu.com/'
        }
        self.session = Session()
        self.login_url = 'https://passport.baidu.com/v2/api/?login'
        self.token = ''
        self.username = ''
        self.password = ''

    def _send(self, reqt, verify=True):
        preped = self.session.prepare_request(reqt)
        resp = self.session.send(preped, verify=verify)
        return resp

    def _get_captcha(self, code_string):
        # Captcha
        if code_string:
            url = "https://passport.baidu.com/cgi-bin/genimage?" + code_string
            reqt = Request('get', url, headers=self.headers)
            captcha = self._send(reqt).content
            verifycode = self.show_captcha(captcha)
        else:
            verifycode = ""
        return verifycode

    def show_captcha(self, captcha):
        with open('captcha.gif', 'wb') as pic:
            pic.write(captcha)
        verifycode = raw_input('Please input captcha > ')
        return verifycode

    def _get_token(self):
        # Token
        url = ('https://passport.baidu.com/v2/api/?getapi&tpl=mn&apiver=v3&class=login&tt=%s&'
               'logintype=dialogLogin&callback=0' % str(time.time()))
        reqt = Request('get', url, headers=self.headers)
        resp = self._send(reqt)
        self.token = eval(resp.content)['data']['token']

    def _get_publickey(self):
        url = 'https://passport.baidu.com/v2/getpublickey?token=' + self.token
        reqt = Request('get', url, headers=self.headers)
        logger.info(reqt.url)
        content = self._send(reqt).content
        jdata = json.loads(content.replace('\'', '"'))
        return (jdata['pubkey'], jdata['key'])

    def login(self):
        # Referred:
        # https://github.com/ly0/baidupcsapi/blob/master/baidupcsapi/api.py
        reqt = Request('get', 'https://pan.baidu.com', headers=self.headers)
        self._send(reqt, verify=False)
        self._get_token()
        pubkey, rsakey = self._get_publickey()
        key = rsa.PublicKey.load_pkcs1_openssl_pem(pubkey)
        password_rsaed = base64.b64encode(rsa.encrypt(self.password, key))
        # 'staticpage': 'http://pan.baidu.com/res/static/thirdparty/pass_v3_jump.html'
        login_data = {'staticpage': 'http://pan.baidu.com/res/static/thirdparty/pass_v3_jump.html',
                      'charset': 'UTF-8',
                      'token': self.token,
                      'tpl': 'pp',
                      'subpro': '',
                      'apiver': 'v3',
                      'tt': str(int(time.time())),
                      'isPhone': 'false',
                      'safeflg': '0',
                      'u': 'http://pan.baidu.com/',
                      'quick_user': '0',
                      'logLoginType': 'pc_loginBasic',
                      'loginmerge': 'true',
                      'logintype': 'basicLogin',
                      'username': self.username,
                      'password': password_rsaed,
                      'mem_pass': 'on',
                      'rsakey': str(rsakey),
                      'crypttype': 12,
                      'ppui_logintime': '50918',
                      'callback': 'parent.bd__pcbs__oa36qm'}
        login_reqt = Request('post', url=self.login_url, data=login_data)
        resp = self._send(login_reqt)

        if 'err_no=257' in resp.content or 'err_no=6' in resp.content:
            code_string = re.findall('codeString=(.*?)&', resp.content)[0]
            captcha = self._get_captcha(code_string)
            login_data['codestring'] = code_string
            login_data['verifycode'] = captcha

        login_reqt_with_captcha = Request('post', url=self.login_url,
                                          data=login_data, headers=self.headers)
        resp = self._send(login_reqt_with_captcha)
        logger.info(resp.content)

    def _create_share_list_params(self, query_uk, start, limit):
        share_list_params = {'t': str(int(time.time())),
                             'category': '0',
                             'auth_type': '1',
                             'request_location': 'share_home',
                             'start': start,
                             'limit': limit,
                             'query_uk': query_uk,
                             'channel': 'chunlei',
                             'clienttype': '0',
                             'web': '1',
                             'bdstoken': 'null'}
        return share_list_params

    def get_share_list(self):
        share_list_url = 'http://yun.baidu.com/pcloud/feed/getsharelist'
        query_params = self._create_share_list_params('1075874930', '200', '20')
        share_list_reqt = Request('get', url=share_list_url, params=query_params)
        share_list_json = self._send(share_list_reqt).json()
        logger.info(share_list_json)
        if share_list_json['errno'] != 0:
            raise GetShareListFailed('Get share list failed with error no. {}'.format(share_list_json['errno']))
        else:
            return share_list_json

    def generate_share_save_reqts(self, share_list_json):
        save_url = 'http://yun.baidu.com/share/transfer'
        for record in share_list_json['records']:
            sour_path = unquote(record['filelist'][0]['path'].encode('utf-8'))
            save_data = {'filelist': '["{}"]'.format(sour_path),  # filelist取第一个，可能有多个，苏菇莨的分享均只有一个
                         'path': u'/书库/苏菇莨/'}
            save_params = {'shareid': record['shareid'],
                           'from': record['uk'],
                           'bdstoken': self.token,
                           'clienttype': '0',
                           'web': '1',
                           'app_id': '250528'
                           }
            self.headers['Referer'] = 'http://yun.baidu.com/s/{}'.format(record['shorturl'])
            save_reqt = Request('post', url=save_url,
                                params=save_params, data=save_data, headers=self.headers)
            yield save_reqt

    def save_all_shares(self):
        self.login()
        shares = self.get_share_list()
        for reqt in self.generate_share_save_reqts(shares):
            resp = self._send(reqt)
            logger.info(resp.json())


if __name__ == '__main__':
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)
    bdc = BaiduShareCrawler()
    bdc.save_all_shares()
