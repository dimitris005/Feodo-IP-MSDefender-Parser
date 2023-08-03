# Feodo-to-MSDefender-Parser

Parser for Botnet IPs from Feodo json format to MS Defender csv

It is created for both Botnet IPs and Domains to be quickly uploaded and blacklisted on MS Defender, as they are acquired for the Feodo Database, aiding in the efficiency of the everyday day tasks of a Threat Intelligence Expert.

The two files, the IP parser and Domain parser, contain the relevant scripts, as well as example inputs and outputs created by running said scripts. The input is a json file that was downloaded from Feodo, while the csv is the format that is tested and accepted by MS Defender.

The scripts are written in Python and utilize pattern matching to identify the relevant information from the json file and then pass that into the csv file we create which follows the exact format that is seen when downloading the example csv that is provided by MS Defender as a template. Only the relevant info is parsed into the csv, while the rest stays hardcoded into set values or just null, as per company policy. This can change easily, as to customize the csv to each ecpert's desires. As such, the script can save time since there is no need of importing data into an excel and then copy-pasting that into the example csv of MS Defender. 
