from scapy.all import ARP, Ether, srp
from flask import Flask, request, jsonify
import requests
import json

app = Flask(__name__)

def scan(ip):
    # Create ARP request packet
    arp_request = ARP(pdst=ip)

    # Create Ethernet frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine Ethernet frame and ARP request
    packet = ether/arp_request

    # Send packet and capture response
    result = srp(packet, timeout=3, verbose=0)[0]

    # Extract the list of devices from the response
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

@app.route('/', methods=['POST'])
def ngrok_webhook():
    data = request.json
    print("Webhook received:")
    print(data)
    print(data["alertData"]["message"])
    # 
    if data["alertData"]["message"] == "trigger-now": 
        # Begin json request to fill data

        url = "https://api.meraki.com/api/v1/organizations/1532658/devices"

        payload = {}
        headers = {
                'Accept': 'application/json',
                'Authorization': 'Bearer 3ca029bc53ba6685a7d30f1d179ed609ed4cc367'
            }

        response = requests.request("GET", url, headers=headers, data=payload)

        #print(response.json())

        # Filter data from Json request for readability
        # if isinstance(data, list):
            # Iterate over each item in the list
        for item in response.json():
                # Check if 'name' attribute exists in the current item
            #print(item['model'])
            if item['model'] == 'MT30':
                # Extract and print the 'name' attribute
                print(item['model'], " ", item['serial']," ", item['mac'])
        
       
    # You can process the data further or store it as needed

    return jsonify({'status': 'success'})

def send_to_webhook(devices):
    # Ngrok public URL for your webhook
    ngrok_url = "https://your-ngrok-subdomain.ngrok.io/webhook"  # Replace with your Ngrok URL

    # Example webhook payload
    payload = {'devices': devices}

    # Send POST request to Ngrok webhook API
    response = requests.post(ngrok_url, json=payload)

    # Check the response
    if response.status_code == 200:
        print("Webhook sent successfully")
    else:
        print(f"Error sending webhook: {response.status_code} - {response.text}")

if __name__ == "__main__":
    # Specify the target IP range
    target_ip = "192.168.128.1/24"

    # Perform the network scan
    devices_list = scan(target_ip)

    # Display the results
    print("Connected devices:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices_list:
        print(f"{device['ip']}\t\t{device['mac']}")

    # Send the results to Ngrok webhook
    # send_to_webhook(devices_list)

    # Run Flask app
    app.run(debug=True)
