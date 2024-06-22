import subprocess
import time
# from pyscript import document

def scan_wifi():
    
    try:
        while True:
           # Execute 'netsh wlan show networks' command to get WiFi networks
            result = subprocess.run(['netsh', 'wlan', 'show', 'network'], capture_output=True, text=True, check=True)
            output = result.stdout.split('\n')

            #Parse the output and print basic information about each network
            for line in output:
                line = line.strip()
                if "SSID" in line:
                    ssid = line.split(":")[1].strip()
                    print(f"SSID: {ssid}")
                elif "Signal" in line:
                    signal = line.split(":")[1].strip()
                    print(f"Signal Strength: {signal}")
                elif "Authentication" in line:
                    auth = line.split(":")[1].strip()
                    print(f"Authentication: {auth}")
                elif "Encryption" in line:
                    enc = line.split(":")[1].strip()
                    print(f"Encryption Type: {enc}")
                    print("")
            print("---------------------New Scan------------------------------")
            time.sleep(5)
    except subprocess.CalledProcessError as e:
        print("Error occurred while scanning WiFi networks:", e)

if __name__ == "__main__":
    print("Scanning for WiFi networks...\n")
    scan_wifi()