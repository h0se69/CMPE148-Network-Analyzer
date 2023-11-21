import io
from CMPE148_Network_App import flaskObj
from flask import jsonify, render_template, redirect, request
from .WireSharkPCAP import get_DNS_host_name, get_list_of_ips, read_pcap_file



flaskObj.config['MAX_CONTENT_LENGTH'] = 400 * 1024 * 1024

@flaskObj.route('/upload', methods=['POST'])
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

            packets = read_pcap_file(file_data)
            list_of_ips = get_list_of_ips(packets)


            return render_template('data.html', list_of_ips=list_of_ips)
        except Exception as e:
            return f"Exception Error processing uploaded file | {e}"

    return render_template('home.html')


@flaskObj.route("/api/get-dns", methods=['POST'])
def get_dns_host_name():
    data = request.get_json()
    ip_address = data.get('ip')
    dns_name  = get_DNS_host_name(ip_address)
    return jsonify({'dns_name': dns_name})

@flaskObj.route("/")
def home():
    return render_template("home.html")