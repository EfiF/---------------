import os
import requests
import time
import json

def FileName(path):
    return os.path.basename(path)

def GetAllFilesInPath(path): # פונקציה המקבלת כתובת של תיקייה ומחזירה את כל הקבצים שנמצאים בתוך התיקייה כולל בתוך התיקיות שבתוך אותה תיקייה
    file_list = []
    
    for root, dirs, files in os.walk(path):
        for file in files:
            file_list = file_list + [os.path.join(root, file)]

    return file_list

# Returs the id of a file scan
def GetVirusTotalIDReport(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    api_key = "33bf4c556085a65ebb483f6fc26ab1e5386f6ed7502c9d3ca948bb4d80f9f7cb"

    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(url, files=files, params={'apikey': api_key})
        data = response.json()
        id = data['scan_id']
        return id

# Returns the full result of a file scan according to it's id
def GetVTScanResult(id):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    api_key = "33bf4c556085a65ebb483f6fc26ab1e5386f6ed7502c9d3ca948bb4d80f9f7cb"

    params = {'apikey': api_key, 'resource': id}
    response = requests.get(url, params=params)

    try:
        data = response.json()
    except json.decoder.JSONDecodeError:
        print(f"Error decoding JSON data for ID: {id}")
        return None

    return data

# Checks if the file is dangerous according to it's data
def isDangerous(data):
    return data['positives'] > 0
    
def GetFileSizeInKB(file_path):
    size_in_bytes = os.path.getsize(file_path)
    return size_in_bytes


def main():
    # Welcome message
    print("Welcome to Efi's virus scanner")

    # Wait 1.5 seconds to display the next line
    time.sleep(1.5)

    # The user enters the path he wants to scan
    path = input("Enter the path of the file you want to scan: ")

    # Wait 0.7 seconds to display the next line
    time.sleep(0.7)

    # The files that are in the folder path
    file_list = GetAllFilesInPath(path)
    
    print("These are the files that are going to be scanned (each file takes approximately 15 seconds to be fully scanned):")

    # Wait 1.5 seconds to display the next line
    time.sleep(1.5)
    for file in file_list:
        print(FileName(file))
        time.sleep(0.8)
    
    time.sleep(0.8)
    print("Results: ")

    for file in file_list:
        # Wait until the file is done scanning
        
        time.sleep(15)

        # Get the id of the scanned file
        id = GetVirusTotalIDReport(file)
        if id:
            data = GetVTScanResult(id)
            if data:
                msg = "is dangerous" if isDangerous(data) else "is not dangerous"
                print(f"{FileName(file)} {msg}")
            else:
                print(f"Error retrieving data for {FileName(file)}")
        else:
            print(f"Error scanning {FileName(file)}")

    time.sleep(1)

    print("Thank you for using Efi's virus scanner! Have a nice day!")


if __name__ == "__main__":
    main()

# This wasn't here before