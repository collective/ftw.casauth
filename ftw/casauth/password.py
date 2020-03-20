# -*- coding: utf-8 -*-
# lifted from CMFPlone.RegistrationTool
import random


def getValidPasswordChars():
    # - remove '1', 'l', and 'I' to avoid confusion
    # - remove '0', 'O', and 'Q' to avoid confusion
    # - remove vowels to avoid spelling words
    invalid_password_chars = ['a', 'e', 'i', 'o', 'u', 'y', 'l', 'q']
    password_chars = []
    for i in range(0, 26):
        if chr(ord('a') + i) not in invalid_password_chars:
            password_chars.append(chr(ord('a') + i))
            password_chars.append(chr(ord('A') + i))
    for i in range(2, 10):
        password_chars.append(chr(ord('0') + i))
    return password_chars


password_chars = getValidPasswordChars()


def generatePassword(length=5, s=None):
    global password_chars

    password = ''
    nchars = len(password_chars)
    for i in range(0, length):
        password += password_chars[random.randint(0, nchars - 1)]
    return password
