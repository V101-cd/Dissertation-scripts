using python-libpcap

Can only run on Linux
  - need to create a venv (virtual environment) in Linux: `python -m venv --system-site-packages env`
  - to run: `source env/bin/activate` (to activate the venv)
  - if you need to install python-libpcap: `pip3 install python-libpcap`
  - to run: cd into the folder where the tool is, then `python libpcap-parser.py [name of pcaps]`
  - to run the packet analysis gui (must be from terminal), cd into the folder where the tool is, then `python packet-analysis-gui-libpcap.py`
  - to end venv session: `deactivate`

  - Need to install `pyqtgraph` within venv: `python -m pip install pyqtgraph`
