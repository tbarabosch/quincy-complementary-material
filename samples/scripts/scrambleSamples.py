# This script scrambles the sample data. It should prevent automatic scanning for samples.
import os
import base64

def scramble(data):
    return base64.b64encode(data)

def storeScrambledFile(encryptedData, path):
    f = open(path + ".scr", "wb")
    f.write(encryptedData)
    f.close()

def main():
    for f in os.listdir(os.path.abspath("..")):
        if ".zip" in f:
            path = os.path.join(os.path.abspath(".."), f)
            data = open(path, "rb").read()
            encryptedData = scramble(data)
            storeScrambledFile(encryptedData, path)

if __name__ == "__main__":
    main()