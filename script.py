import requests
import time
import os

url = 'https://www.virustotal.com/vtapi/v2/file/scan'
api_key = "33bf4c556085a65ebb483f6fc26ab1e5386f6ed7502c9d3ca948bb4d80f9f7cb"

# Gets a file path and returns his name + extension
def File_Name(file_path):
    return os.path.basename(file_path)

# Organizes each file that was found in the path to a list
def Get_All_Files_In_Path(path): 
    file_list = []
    
    for root, dirs, files in os.walk(path):
        for file in files:
            file_list = file_list + [os.path.join(root, file)]

    return file_list

# Scans the file
def Scan_File(file_path, api_key, url):
    files = {'file': (file_path, open(file_path, 'rb'))}
    params = {'apikey': api_key}
    response = requests.post(url, files=files, params=params)
    return response

# Returns the ID of the scan
def Scan_Id(response):
    return response.json()['scan_id']

# Gets the result of the scan
def Get_Scan_Result(scan_id):
    params = {'apikey': api_key, 'resource': scan_id}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    return response


# Checks if the file is dangerous
def Is_Dangerous(response):
    try:
        json_response = response.json()
        return json_response.get('positives', 0) > 0
    except ValueError:
        # If an error has occured, wait 10 seconds and then try again
        print("An error has occured. Rescanning the file...")
        time.sleep(10)

        # Calls the function again in order to get a response
        return Is_Dangerous(response)


def main():
    time.sleep(0.6)
    print("Welcome to Efi's new AntiVirus")

    time.sleep(0.7)
    folder_path = input("Enter the path of the folder to scan: ")

    time.sleep(0.7)
    print("These are the files that will be scanned: ")

    time.sleep(0.7)
    for file_path in Get_All_Files_In_Path(folder_path):
        time.sleep(0.5)
        print(File_Name(file_path))

    time.sleep(1)
    print("Scanning files...")

    time.sleep(0.7)
    for file_path in Get_All_Files_In_Path(folder_path):
        
        response = Scan_File(file_path, api_key, url)
        
        id = Scan_Id(response)

        response = Get_Scan_Result(id)

        if Is_Dangerous(response):
            print(f"The following file is malicious: {File_Name(file_path)}")
        else:
            print(f"{File_Name(file_path)} is safe")
        
        # Wait 5 seconds between each scan to avoid bugs
        time.sleep(5)

    time.sleep(1.2)
    print("Thank you for using Efi's new AntiVirus")

    rating = int(input("Please rate the program from 1 to 5: "))
    while rating < 1 or rating > 5:
        rating = int(input("Please enter a number between 1 and 5: "))
        
    time.sleep(0.7)
    print("Thank you for your feedback!")

if __name__ == "__main__":
    main()
