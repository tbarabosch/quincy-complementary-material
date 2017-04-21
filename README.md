# Quincy Complementary Material
This repository contains complementary material of the [DIMVA 2017](https://itsec.cs.uni-bonn.de/dimva2017/) publication "Quincy: Detecting Host-Based Code Injection
Attacks in Memory Dumps". It contains:

* hashes: hashes of benign and malicious programs used in the evaluation
* samples: malware samples used in the evaluation
* yara: yara signatures for detecting these malware samples in memory

Please refer to the publication for more information about Quincy and its evaluation.

## Hashes of Benign Programs

We listed the hashes of the benign programs that were used in the evaluation. There is one list for each operating
system.

## Code-Injecting Malware Samples

We evaluated Quincy with these malware samples. Use with caution, they may be still live malware!! 

We also included for some samples raw dumps of the malware extracted from memory. Furthermore, we added a CSV file with the sample dates (according to VirusTotal First Time Seen) that was used in the temporal evaluation of Quincy.

The samples and dumps are "scrambled" with base64 to avoid automatic scanning. Use the script descrambleSamples.py to descramble locally. Password of resulting zip files is "infected" without quotes.  

## Yara Signatures 

These yara signatures were used in the evaluation in order to confirm successfull injections. Many of them work pretty
well on many versions of the corresponding malware family. Some of the yara rules were especially tailored
for the sample at hand and might not work with other samples/versions of the malware family. They also may result in false positives, use at own risk! 
Our main intention was not writing general rules but rather rules for ensuring high data quality in the evaluation.

The yara signatures are unfortunately incomplete. The rules of some families could not be published due to their
classification. However, we might share them on a 1-to-1 basis depending on your reputation and/or organization.
Contact us for more information (thomas.barabosch at gmail.com).