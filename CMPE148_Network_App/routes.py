import io
from CMPE148_Network_App import flaskObj
from flask import jsonify, render_template, redirect, request, session
from .WireSharkPCAP import get_DNS_host_name, get_list_of_ips, read_pcap_file, perform_flow_analysis



flaskObj.config['MAX_CONTENT_LENGTH'] = 400 * 1024 * 1024

@flaskObj.route('/upload', methods=['POST', 'GET'])
def upload_file():
    if request.method == 'POST':
        if 'pcap_file' not in request.files:
            return "No File Found in Request"

        file = request.files['pcap_file']

        if file.filename == '':
            return "No File Found"
        if file.content_length > flaskObj.config['MAX_CONTENT_LENGTH']:
            return "File is over allowed size limit"

        try:
            uploaded_user_file = file.read()
            file_data = io.BytesIO(uploaded_user_file)

            # Use the WireSharkPCAP module functions
            packets = read_pcap_file(file_data)
            list_of_ips = get_list_of_ips(packets)

            # Save the uploaded pcap file to a temporary location
            # You might want to store it in a more organized manner in a production environment
            temp_pcap_path = "temp_upload.pcap"
            with open(temp_pcap_path, 'wb') as temp_pcap_file:
                temp_pcap_file.write(uploaded_user_file)

            # Store the temp_pcap_path in the session for later use
            session['temp_pcap_path'] = temp_pcap_path

            # Redirect to data.html
            return redirect('/data')
        except Exception as e:
            return f"Exception Error processing uploaded file | {e}"

    return render_template('home.html')


@flaskObj.route("/api/get-dns", methods=['POST'])
def get_dns_host_name():
    data = request.get_json()
    ip_address = data.get('ip')
    dns_name = get_DNS_host_name(ip_address)
    return jsonify({'dns_name': dns_name})

@flaskObj.route("/data")
def data():
    # Retrieve the temp_pcap_path from the session
    temp_pcap_path = session.get('temp_pcap_path')

    if temp_pcap_path:
        # Use WireSharkPCAP functions for data analysis
        packets = read_pcap_file(temp_pcap_path)
        list_of_ips = get_list_of_ips(packets)

        return render_template('data.html', list_of_ips=list_of_ips)
    else:
        # If temp_pcap_path is not available, redirect to home.html
        return redirect('/')


@flaskObj.route("/flow_analysis")  # Change the route to something more appropriate like "/flow_analysis"
def flow_analysis():
    # Retrieve the temp_pcap_path from the session
    temp_pcap_path = session.get('temp_pcap_path')

    if temp_pcap_path:
        # Use new flow analysis function
        flow_data = perform_flow_analysis(temp_pcap_path)

        return render_template('flow_analysis.html', flow_data=flow_data)
    else:
        # If temp_pcap_path is not available, redirect to home.html
        return redirect('/')

@flaskObj.route("/")
def home():
    return render_template("home.html")