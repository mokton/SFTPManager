#!/usr/bin/python3.6
# -*- coding: UTF-8 -*-

import os
import argparse
import pwd 
import grp
import shutil
import crypt
from random import choice
import fileinput


_chars_set = r'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&<>-_.,='
_here = os.path.dirname(__file__)
_passwd = os.path.join(_here, 'passwd')


def random_string(length=20):
    result = ''
    for i in range(length):
        result += choice(_chars_set)
    return result


def get_args():
    # 创建解析步骤
    parser = argparse.ArgumentParser(description='Sftp user manager.')

    # 添加参数步骤
    # parser.add_argument('integers', metavar='N', type=int, nargs='+',
    #                    help='an integer for the accumulator')
    # parser.add_argument('--sum', dest='accumulate', action='store_const',
    #                    const=sum, default=max,
    #                    help='sum the integers')

    parser.add_argument('Username', type=str, metavar='User', help="Username for deeling.")

    parser.add_argument('-a', '--action', type=str, dest='Action',
                        help="Command action.", default='add', choices=['add', 'delete', 'password'])

    parser.add_argument('-d', '--department', type=str, dest='Department',
                        help="User's department.", default='common', 
                        choices=['development', 'engineering', 'administration', 'executive', 'common'])

    parser.add_argument('-p', '--password', type=str, dest='Password',
                        help="User's  password.", default='')

    parser.add_argument('-R', '--root', type=str, dest='Chroot_dir',
                        help="chroot dectionary", default='/mnt/nas')

    # 解析参数步骤  
    args = parser.parse_args()
    # print(args.accumulate(args.d))

    # print("argparse.args=",args,type(args))
    # d = args.__dict__
    # for key,value in d.items():
    #     print('%s = %s'%(key,value))
    return args


def check_user(user):
    exist = False
    try:
        pwd.getpwnam(user)
        exist = True
    except KeyError:
        exist = False
    return exist


def sftpPasswd(action, username, password=None, department=None, passwd_file=None):
    filename = passwd_file if passwd_file else _passwd

    if action == 'add':
        with open(filename, 'a', encoding='utf-8') as fp:
            fp.write('{username}:{password}:{department}\n'.format(username=username, password=password, department=department))
    elif action == 'delete':
        with fileinput.input(files=filename, inplace=True) as fp:
            for line in fp:
                if username == line[:len(username)] and ':' == line[len(username):len(username) + 1]:
                    pass
                else:
                    print(str(line).strip())
    elif action == 'password':
        with fileinput.input(files=filename, mode='r', inplace=True) as fp:
            for line in fp:
                if username == line[:len(username)] and ':' == line[len(username):len(username) + 1]:
                    user = str(line).split(':')
                    print(str(line).strip().replace(user[1], password))
                else:
                    print(str(line).strip())
    os.chmod(filename, mode=0o600)


def sftpUser(user: dict):
    user_username = user.Username
    action = user.Action
    department = user.Department
    root = user.Chroot_dir
    password = user.Password
    if password == '':
        password = random_string(32)
    user_root = os.path.join(root, department, user_username)
    user_private = os.path.join(user_root, 'private')
    user_password = crypt.crypt(password, 'witlink@20191018')
    if action == 'add':
        if check_user(user_username):
            print('User "{}" already exist.'.format(user_username))
            return

        if os.path.exists(user_root):
            shutil.rmtree(user_root)
        os.system('useradd -d {user_root} -s /usr/sbin/nologin -g nas -p {password} -m {user}'.format(user_root=user_root, password=user_password, user=user_username))
        user_pw = pwd.getpwnam(user_username)
        os.chown(user_root, user_pw.pw_uid, user_pw.pw_gid)
        os.chmod(user_root, mode=0o751)
        os.makedirs(user_private, exist_ok=True)
        os.chmod(user_private, mode=0o700)
        os.chown(user_private, user_pw.pw_uid, user_pw.pw_gid)
        print('User "{}" has been added successfully!\n'.format(user_username))
        print('\n[Important] PASSWORD: {}\n'.format(password))

    elif action == 'delete':
        if not check_user(user_username):
            print('User "{}" does not exist.'.format(user_username))
            return

        user_pw = pwd.getpwnam(user_username)
        os.system('userdel {}'.format(user_username))
        os.system('rm -rf {}'.format(user_pw.pw_dir))
        print('User "{}" has been deleted successfully!\n'.format(user_username))

    elif action == 'password':
        if not check_user(user_username):
            print('User "{}" does not exist.'.format(user_username))
            return

        os.system('usermod -p {password} {user}'.format(password=user_password, user=user_username))
        print('Change user {}\'s password successfully!\n'.format(user_username))
        print('\n[Important] PASSWORD: {}\n'.format(password))

    sftpPasswd(action, user_username, password, department)


def test_sftpPasswd():
    os.remove(_passwd)
    for i in range(10):
        sftpPasswd('add', 'user' + str(i), random_string(), department='development')
    sftpPasswd('password', 'user5', random_string())
    sftpPasswd('password', 'user7', random_string())
    sftpPasswd('password', 'user3', random_string())
    sftpPasswd('delete', 'user2', random_string())
    sftpPasswd('delete', 'user3', random_string())
    sftpPasswd('delete', 'user9', random_string())


if __name__ == '__main__':
    args = get_args()

    print()
    sftpUser(args)

    # test_sftpPasswd()
    #
    # pass

    # gpasswd -d user group
