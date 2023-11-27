import io
import json
from CMPE148_Network_App import flaskObj
from flask import jsonify, render_template, redirect, request, session, url_for
from .WireSharkPCAP import get_DNS_host_name, get_list_of_ips, get_packet_sizes, read_pcap_file

flaskObj.config['MAX_CONTENT_LENGTH'] = 400 * 1024 * 1024 # limit file size to 400MB idk if we can handle huge files lol
stored_packets = []

@flaskObj.route('/upload', methods=['POST'])
def upload_file():
    global stored_packets
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
            stored_packets = packets

            list_of_ips = get_list_of_ips(packets)

            session['list_of_ips'] = list_of_ips
            session['is_upload_file_present'] = True

            return redirect(url_for('view_packet_ips'))
        except Exception as e:
            return f"Exception Error processing uploaded file | {e}"
    return render_template('home.html')


@flaskObj.route("/view-packet-data/ips")
def view_packet_ips():
    global stored_packets
    list_of_ips = session.get('list_of_ips', {})
    is_upload_file_present = session.get('is_upload_file_present', {})

    if(list_of_ips != {} and is_upload_file_present and stored_packets):
        return render_template('data.html', list_of_ips=list_of_ips)
    else:
        return render_template('error.html', error_msg= "Please upload a PCAP file to see IPS")


@flaskObj.route('/view-packet-data/packets/<int:page>')
def view_packets(page=1):
    global stored_packets
    is_upload_file_present = session.get('is_upload_file_present', {})

    if stored_packets and is_upload_file_present:
        packet_info_list, total_pages = get_packet_sizes(stored_packets, page)
        return render_template('packet_data.html', packet_info_list=packet_info_list, page=page, total_pages=total_pages)
    else:
        return render_template('error.html', error_msg= "Please upload a PCAP file to see Packet Data")


@flaskObj.route("/api/get-dns", methods=['POST'])
def get_dns_host_name():
    data = request.get_json()
    ip_address = data.get('ip')
    dns_name  = get_DNS_host_name(ip_address)
    return jsonify({'dns_name': dns_name})

@flaskObj.route("/")
def home():
    return render_template("home.html")