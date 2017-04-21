# This script descrambles the sample data locally on your hard disk.
import os
import base64

def descramble(data):
    return base64.b64decode(data)

def storeDescrambledFile(encryptedData, path):
    f = open(path.replace(".scr", ""), "wb")
    f.write(encryptedData)
    f.close()

def main():
    for f in os.listdir(os.path.abspath("..")):
        if ".zip.scr" in f:
            path = os.path.join(os.path.abspath(".."), f)
            data = open(path, "rb").read()
            encryptedData = descramble(data)
            storeDescrambledFile(encryptedData, path)

if __name__ == "__main__":
    main()