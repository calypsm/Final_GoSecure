# import pywifi
# import time
# from tabulate import tabulate

# def scan_wifi():
#     wifi = pywifi.PyWiFi()
#     iface = wifi.interfaces()[0]
#     iface.scan()
#     time.sleep(2)

#     scan_results = iface.scan_results()
#     return scan_results

# def print_wifi_list(wifi_list):
#     unique_networks = {}
#     for result in wifi_list:
#         ssid = result.ssid
#         if ssid not in unique_networks:
#             unique_networks[ssid] = [result.signal, result.akm[0] if result.akm else "Open"]

#     table = []
#     for index, (ssid, data) in enumerate(unique_networks.items(), 1):
#         signal_strength, security = data
#         table.append([index, ssid, signal_strength, security])

#     headers = ["No.", "SSID", "Signal Strength", "Security"]
#     print(tabulate(table, headers, tablefmt="pretty"))

# def runScan():
#     wifi_list = scan_wifi()
#     print_wifi_list(wifi_list)


# ini beda lagi bro (2)
# import ctypes
# import ctypes.wintypes
# import time

# class GUID(ctypes.Structure):
#     _fields_ = [
#         ('Data1', ctypes.wintypes.DWORD),
#         ('Data2', ctypes.wintypes.WORD),
#         ('Data3', ctypes.wintypes.WORD),
#         ('Data4', ctypes.c_ubyte * 8)
#     ]

# class WLAN_INTERFACE_INFO(ctypes.Structure):
#     _fields_ = [
#         ('InterfaceGuid', GUID),
#         ('strInterfaceDescription', ctypes.c_wchar * 256),
#         ('isState', ctypes.wintypes.DWORD)
#     ]

# class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
#     _fields_ = [
#         ('dwNumberOfItems', ctypes.wintypes.DWORD),
#         ('dwIndex', ctypes.wintypes.DWORD),
#         ('InterfaceInfo', WLAN_INTERFACE_INFO * 1)
#     ]

# class DOT11_SSID(ctypes.Structure):
#     _fields_ = [
#         ('uSSIDLength', ctypes.wintypes.ULONG),
#         ('ucSSID', ctypes.c_char * 32)
#     ]

# class WLAN_AVAILABLE_NETWORK(ctypes.Structure):
#     _fields_ = [
#         ('strProfileName', ctypes.c_wchar * 256),
#         ('dot11Ssid', DOT11_SSID),
#         ('dot11BssType', ctypes.wintypes.DWORD),
#         ('uNumberOfBssids', ctypes.wintypes.ULONG),
#         ('bNetworkConnectable', ctypes.wintypes.BOOL),
#         ('wlanNotConnectableReason', ctypes.wintypes.DWORD),
#         ('uNumberOfPhyTypes', ctypes.wintypes.ULONG),
#         ('dot11PhyTypes', ctypes.wintypes.DWORD * 8),
#         ('bMorePhyTypes', ctypes.wintypes.BOOL),
#         ('wlanSignalQuality', ctypes.wintypes.DWORD),
#         ('bSecurityEnabled', ctypes.wintypes.BOOL),
#         ('dot11DefaultAuthAlgorithm', ctypes.wintypes.DWORD),
#         ('dot11DefaultCipherAlgorithm', ctypes.wintypes.DWORD),
#         ('dwFlags', ctypes.wintypes.DWORD),
#         ('dwReserved', ctypes.wintypes.DWORD)
#     ]

# class WLAN_AVAILABLE_NETWORK_LIST(ctypes.Structure):
#     _fields_ = [
#         ('dwNumberOfItems', ctypes.wintypes.DWORD),
#         ('dwIndex', ctypes.wintypes.DWORD),
#         ('Network', WLAN_AVAILABLE_NETWORK * 1)
#     ]

# def get_wifi_windows():
#     wlanapi = ctypes.windll.LoadLibrary('wlanapi.dll')
#     handle = ctypes.c_void_p()
#     negotiated_version = ctypes.c_ulong()

#     # Open handle
#     wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated_version), ctypes.byref(handle))

#     # Enumerate interfaces
#     p_interface_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
#     wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(p_interface_list))
#     interface_list = p_interface_list.contents

#     networks = []
#     for i in range(interface_list.dwNumberOfItems):
#         interface_info = interface_list.InterfaceInfo[i]

#         # Scan for available networks
#         wlanapi.WlanScan(handle, ctypes.byref(interface_info.InterfaceGuid), None, None, None)
#         time.sleep(5)  # Wait for the scan to complete

#         # Get available networks
#         p_network_list = ctypes.POINTER(WLAN_AVAILABLE_NETWORK_LIST)()
#         wlanapi.WlanGetAvailableNetworkList(handle, ctypes.byref(interface_info.InterfaceGuid), 0, None, ctypes.byref(p_network_list))
#         network_list = ctypes.cast(p_network_list, ctypes.POINTER(WLAN_AVAILABLE_NETWORK_LIST)).contents

#         # Correctly create a list of WLAN_AVAILABLE_NETWORK structures
#         network_array_type = WLAN_AVAILABLE_NETWORK * network_list.dwNumberOfItems
#         network_array = ctypes.cast(ctypes.addressof(network_list.Network), ctypes.POINTER(network_array_type)).contents

#         for j in range(network_list.dwNumberOfItems):
#             network = network_array[j]
#             ssid = network.dot11Ssid.ucSSID[:network.dot11Ssid.uSSIDLength].decode(errors='ignore')
#             signal = network.wlanSignalQuality
#             security = "Encrypted" if network.bSecurityEnabled else "Open"
#             networks.append({'SSID': ssid, 'Signal': signal, 'Security': security})

#         wlanapi.WlanFreeMemory(p_network_list)

#     wlanapi.WlanFreeMemory(p_interface_list)
#     wlanapi.WlanCloseHandle(handle, None)
#     return networks

# def print_wifi_list(networks):
#     print(f"{'No.':<4}{'SSID':<30}{'Signal':<20}{'Security':<20}")
#     print('-' * 74)
#     for index, network in enumerate(networks, start=1):
#         print(f"{index:<4}{network['SSID']:<30}{network['Signal']:<20}{network['Security']:<20}")

# if __name__ == "__main__":
#     networks = get_wifi_windows()
#     print_wifi_list(networks)


#signal percent
import subprocess

def scan_wifi_windows():
    result = subprocess.run(['netsh', 'wlan', 'show', 'network', 'mode=Bssid'], capture_output=True, text=True, check=True)
    return result.stdout

def parse_wifi_windows(scan_output):
    networks = []
    lines = scan_output.split('\n')
    network = {}
    for line in lines:
        line = line.strip()
        if line.startswith('SSID'):
            if network:
                networks.append(network)
                network = {}
            network['SSID'] = line.split(':')[1].strip()
        elif line.startswith('Signal'):
            network['Signal'] = line.split(':')[1].strip()
        elif line.startswith('Authentication'):
            network['Security'] = line.split(':')[1].strip()
    if network:
        networks.append(network)
    return networks

def print_wifi_list(networks):
    print(f"{'No.':<4}{'SSID':<30}{'Signal':<20}{'Security':<20}")
    print('-' * 74)
    for index, network in enumerate(networks, start=1):
        print(f"{index:<4}{network['SSID']:<30}{network['Signal']:<20}{network['Security']:<20}")

def run_scan():
    scan_output = scan_wifi_windows()
    networks = parse_wifi_windows(scan_output)
    print_wifi_list(networks)

if __name__ == "__main__":
    run_scan()

