# Code and User Documentation
This tool has been developed as part of an Undergraduate Computer Science dissertation, to aid non-expert Networking users in visualising and analysing Internet packets.

## Code 
The code for this tool is available from [https://github.com/V101-cd/Dissertation-scripts.git](https://github.com/V101-cd/Dissertation-scripts.git)
## System Requirements 
The tool only runs on native Linux devices (i.e. not Linux hypervisors or virtual machines). 
## Running the tool 
1. Download the folder from https://github.com/V101-cd/Dissertation-scripts.git 

2. In the terminal, create a virtual environment (venv):

     `python -m venv --system-site-packages env `

3. Activate the venv (_note: replace ’env’ with whatever you named your venv in step 2_): 

     `source env/bin/activate `

4. Navigate to the folder where the tool is located 

5. Install the required packages by running (_note: you may need to use pip3 instead of pip_): 

     `pip install -r requirements.txt ` 

6. Run the tool using: 

     `python packet-analysis-gui-libpcap.py `

7. When you are finished using the tool, end the venv session: 

     `deactivate `
## Generating pcaps to use in the tool 
The tool requires you to import a packet capture file (.pcap, or pcap) into the tool before you 
can visualise or analyse any packets. 

The tool will let you import any pcaps you already have, or you can capture your own Internet traffic 
as a pcap using the following command on a native Linux device: 

`tcpdump -i eth0 -v -w my_captured_TCPDump.pcap `

eth0 is an Ethernet interface, but you can change this to any other interface available. You 
can view available interfaces by running: 

`tcpdump –-list-interfaces `
