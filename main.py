import binascii
import math
import sys
import threading
import time
from tkinter import *
import socket
import select
import os
import random
global thread_status

server_switch = False
keep_alive_flag = True
keep_alive_end = False
keep_alive_stop = False
switch_roles_flag = False
lock = threading.Lock()
server_loop = True
client_loop = True
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_port = 0;
sending_message = False
recieving_message = False
sending_file = False
recieving_file = False
stop_client = False



# ================================================================
#
# ================================================================
def PRINT_ERROR(role, strArg, message):
    tb_output_text.configure(state='normal')
    tb_output_text.insert('end', role, "bold")
    tb_output_text.insert('end', strArg + message + '\n', "errormsg")
    tb_output_text.configure(state='disabled')
    tb_output_text.see("end")

def PRINT_INFO(role, strArg, message):
    tb_output_text.configure(state='normal')
    tb_output_text.insert('end', role, "bold")
    tb_output_text.insert('end', strArg + message + '\n')
    tb_output_text.configure(state='disabled')
    tb_output_text.see("end")
# ================================================================
# LOGGER
# ================================================================


def dbg(*args, **kwargs):
    frame_obj = sys._getframe(1)  # currentframe()  # get frame of caller function
    line = frame_obj.f_lineno  # source code line number of caller place
    code_obj = frame_obj.f_code  # source code object ( method or function object )
    file_name = code_obj.co_filename  # file name of source code object

    msg = "{0}:{1:<4};".format(file_name.rjust(64), line)
    ct = threading.current_thread()
    msg += "{0:6}; {1};".format(ct.ident, ct.name.ljust(24))
    for a in args:
        msg += "{} ".format(a)
    for k, v in reversed(kwargs.items()):
        msg += "{}={} ".format(k, v)
    with lock:
        print(msg)

# ================================================================
# INITIALIZE GUI
# ================================================================

def initialize():
    global tb_port, tb_ip, chb_server, chb_client, chb_server_checked, chb_client_checked, btn_start, tb_output_text, tb_packet_size, tb_message, chb_errors, chb_errors_checked
    # WINDOW
    window = Tk()
    window.title("UDP Chat aplication")
    window.geometry("680x580")

    # LABELS
    lbl_port = Label(text="PORT:")
    lbl_port.place(x=45, y=50)
    lbl_ip = Label(text="Ip Address:")
    lbl_ip.place(x=20, y=80)
    lbl_packet_size = Label(text="Packet Size:")
    lbl_packet_size.place(x=20, y=530)

    # TEXTBOXES
    tb_port = Text(height=1, width=5)
    tb_port.insert(END, "8080")
    tb_port.place(x=85, y=50)
    tb_ip = Text(height=1, width=15)
    tb_ip.insert(END, "127.0.0.1")
    tb_ip.place(x=85, y=80)
    tb_packet_size = Text(height=1, width=5)
    tb_packet_size.place(x=85, y=530)
    tb_message = Text(height=1, width=40)
    tb_message.place(x=135, y=530)

    # CHECKBOXES
    chb_server_checked = IntVar()
    chb_client_checked = IntVar()
    chb_errors_checked = IntVar()
    chb_server = Checkbutton(text="Server", variable=chb_server_checked, command=on_check_server)
    chb_server.place(x=300, y=50)
    chb_client = Checkbutton(text="Client", variable=chb_client_checked, command=on_check_client)
    chb_client.place(x=300, y=80)
    chb_errors = Checkbutton(text="Errors", variable=chb_errors_checked, ) #command=on_check_errors
    chb_errors.place(x=580, y=530)

    # BUTTONS
    btn_start = Button(window, text="Start", command=btn_start_click, width=10)
    btn_start.place(x=555, y=50)
    btn_stop = Button(window, text="Stop", command=btn_stop_click, width=6)
    btn_stop.place(x=480, y=50)
    btn_switch = Button(window, text="Switch", command=btn_switch_click,  width=10)
    btn_switch.place(x=555, y=80)
    btn_message = Button(window, text="Message", command=btn_message_click)
    btn_message.place(x=470, y=530)
    btn_file = Button(window, text="File", command=btn_file_click)
    btn_file.place(x=540, y=530)

    # MULTILINE TEXTBOX
    chatBox = Scrollbar(window)
    tb_output_text = Text(window, wrap='word', state='disabled', width=78, font="Helvetica 10", yscrollcommand=chatBox.set)
    tb_output_text.tag_configure("bold", font="Helvetica 10 bold")
    tb_output_text.tag_configure("errormsg", font="Helvetica 10", foreground="red")
    chatBox.configure(command=tb_output_text.yview)
    tb_output_text.place(x=85, y=120)

    window.mainloop()

# ================================================================
# BUTTON START CLICK EVENT
# ================================================================

def btn_start_click():
    dbg("btn_start_click")
    btn_start["text"] = "Running"
    btn_start["bg"] = "light green"
    btn_start["disabledforeground"] = "black"
    btn_start["state"] = DISABLED
    start()

# ================================================================
# BUTTON SWITCH CLICK EVENT
# ================================================================

def btn_switch_click():

    dbg("btn_switch_click")
    global switch_roles_flag, server_loop, chb_server_checked, server_switch
    if chb_server_checked.get() == 1:
        server_switch = True
    else:
        switch_roles_flag = True
        server_loop = False

# ================================================================
# BUTTON STOP CLICK EVENT
# ================================================================

def btn_stop_click():
    global stop_client, keep_alive_flag
    stop_client = True
    btn_start["text"] = "Start"
    btn_start["bg"] = "white"
    #btn_start["disabledforeground"] = "black"
    btn_start["state"] = NORMAL

# ================================================================
# BUTTON MESSAGE CLICK
# ================================================================

def btn_message_click():
    global sending_message
    sending_message = True

# ================================================================
# BUTTON FILE CLICK
# ================================================================

def btn_file_click():
    global sending_file
    sending_file = True

# ================================================================
# CHECK BOX EVENTS
# ================================================================

def on_check_client():
    if chb_client_checked.get() == 1:
        chb_client["fg"] = "green"
    else:
        chb_client["fg"] = "red"

def on_check_server():
    if chb_server_checked.get() == 1:
        chb_server["fg"] = "green"
    else:
        chb_server["fg"] = "red"

# ================================================================
#  CLIENT, SERVER AND KEEPALIVE THREAD
# ================================================================

def client_thread():
    return threading.Thread(target=client_login)

def server_thread():
    return threading.Thread(target=server_login)

def keep_alive_thread(client_socket, server_address, interval):
    return threading.Thread(target=keep_alive, args=(client_socket, server_address, interval))

# ================================================================
#   KEEP ALIVE
# ================================================================

def keep_alive(client_sock, server_addr, interval):
    global keep_alive_end, keep_alive_stop
    while keep_alive_flag:

        if keep_alive_stop:
            time.sleep(3)
            continue

        if switch_roles_flag:
            PRINT_INFO("Client: ", "Keep Alive is OFF", " ")
            break

        client_sock.setblocking(1)
        client_sock.sendto(str.encode('4'), server_addr)
        data = client_sock.recv(1500)
        info = str(data.decode())

        if info == '4':
            PRINT_INFO("Client: ", "Connection is working", " ")

        else:
            PRINT_INFO("Client: ", "Connection ended", " ")
            break
        time.sleep(interval)
    keep_alive_end = True
    dbg("keep alive end")

# ================================================================
#   HEADER
# ================================================================
def check_sum_file(packet_id, packet_type, packet_data):
    global chb_errors_checked
    checksum = ''
    errors = 0
    if chb_errors_checked.get() == 1:
        errors = random.randint(0, 1)
        dbg("ERROR:", errors)
    crc_checksum = 0
    crc_checksum = binascii.crc32(packet_data, 0)
    crc_checksum -= errors
    count = len(packet_id) + len(packet_type) + len(packet_data) + 32 + errors
    checksum = format(count, 'b')
    return crc_checksum

def check_sum(packet_id, packet_type, packet_data):
    global chb_errors_checked
    checksum = ''
    errors = 0
    if chb_errors_checked.get() == 1:
        errors = random.randint(0, 1)

    crc_checksum = 0
    packet_data_bytes = bytes(packet_data, 'utf-8')
    crc_checksum = binascii.crc32(packet_data_bytes, 0)
    crc_checksum += errors
    count = len(packet_id) + len(packet_type) + len(packet_data) + 32 + errors
    checksum = format(count, 'b')
    return crc_checksum

def check_sum_server_file(packet_id, packet_type, checksum, packet_data):

    crc_checksum_server = binascii.crc32(packet_data, 0)
    return crc_checksum_server

def check_sum_server(packet_id, packet_type, checksum, packet_data):
    crc_checksum_server = 0
    data = decode_binary_string(packet_data)
    data_binary = bytes(data, "utf-8")
    crc_checksum_server = binascii.crc32(data_binary, 0)
    return crc_checksum_server

def header(id, type, data, p_size):
    id_size = 24
    checksum_size = 32
    checksum = ""
    packet = 0
    type_size = 16
    packet_id = format(id, 'b')
    packet_type = ''.join(format(i, '08b') for i in bytearray(str(type), encoding='utf-8'))
    temp_packet_data = data[id*int(p_size):id*int(p_size)+int(p_size)]

    if len(packet_id) < id_size:
        for i in range(id_size - len(packet_id)):
            packet_id = ''.join(('0', packet_id))

    checksum = check_sum(packet_id, packet_type, temp_packet_data)
    checksum_encoded = format(checksum, 'b')
    packet_data = ''.join(format(i, '08b') for i in bytearray(str(temp_packet_data), encoding='utf-8'))
    if len(checksum_encoded) < checksum_size:
        for i in range(checksum_size - len(checksum_encoded)):
            checksum_encoded = ''.join(('0', checksum_encoded))
    packet = packet_id + packet_type + checksum_encoded + packet_data
    return packet

def header_file(id, type, data, p_size):
    id_size = 24
    checksum_size = 32
    checksum = ""
    packet = 0
    type_size = 16
    checksum_encoded = ""
    packet_id = format(id, 'b')
    packet_type = ''.join(format(i, '08b') for i in bytearray(str(type), encoding='utf-8'))
    packet_data = data[id*int(p_size):id*int(p_size)+int(p_size)]
    #packet_data = ''.join(format(i, '08b') for i in bytearray(str(temp_packet_data), encoding='utf-8'))
    if len(packet_id) < id_size:
        for i in range(id_size - len(packet_id)):
            packet_id = ''.join(('0', packet_id))

    if type == "20":
        checksum = check_sum_file(packet_id, packet_type, packet_data)
        checksum_encoded = format(checksum, 'b')
        if len(checksum_encoded) < checksum_size:
            for i in range(checksum_size - len(checksum_encoded)):
                checksum_encoded = ''.join(('0', checksum_encoded))
    packet = packet_id + packet_type + checksum_encoded
    return packet

def decode_binary_string(s):
    return ''.join(chr(int(s[i*8:i*8+8],2)) for i in range(len(s)//8))
# ================================================================
#   RECIEVE MESSAGE
# ================================================================

def recieve_message(server_sock):
    dbg("now I am ready to recieve, send me total num of packet first")

    # wait for initial message from client thats says he is going to send message
    data = server_sock.recvfrom(1500)
    stored_id = ["" for x in range(int(data[0]))]
    stored_data = ["" for x in range(int(data[0]))]
    checksum_server = ""
    message = ""

    dbg("total num of packets is:", data[0])
    server_sock.sendto(str.encode("25"), data[1]) # 25 from server to client to start sending packets
    PRINT_INFO("Server: ", "Total packet number from Client will be: ", str(data[0].decode()))
    while True:
        #
        packet = server_sock.recvfrom(1500)
        p_type = str(packet[0].decode())
        if p_type == "21": # or if packet id = total num of packets
            break
        checksum_server = check_sum_server(packet[0][0:24], packet[0][24:40], packet[0][40:72], packet[0][72:])
        if(checksum_server != int(packet[0][40:72], 2)):
            dbg("Packet mi dosiel poskodeny, posli mi ho znovu")
            server_sock.sendto(str.encode("-1"), data[1])
            PRINT_ERROR("Client: ", "Recieved invalid packet: ", str(int(packet[0][0:24], 2)))
            continue;

        stored_data[int(packet[0][0:24], 2)] = decode_binary_string(packet[0][72:])
        dbg("Odosielam ACK")
        packet_no = str(int(packet[0][0:24], 2))
        server_sock.sendto(str.encode(packet_no), data[1])
        PRINT_INFO("Client: ", "Recieved packet: ", str(int(packet[0][0:24], 2)))
        PRINT_INFO("Client: ", "Length: ", str(len(packet[0])))


    for data in stored_data:
        message += data
    PRINT_INFO("Recieved Message:", " ", str(message))
    PRINT_INFO("Server: ", "Message Size: ", str(len(message)))

# ================================================================
#   SEND MESSAGE
# ================================================================

def send_message(client_socket, server_address):
    PRINT_INFO("Client: ", "I am going to send message", " ")
    dbg("I am going to calculate packet size and so on")
    client_socket.sendto(str.encode("19"), server_address)  # 19 - idem posielat spravu, tak sa priprav
    client_socket.recvfrom(1500)
    # wait for server to listen for messages
    time.sleep(1)

    packet_size = tb_packet_size.get("1.0", "end-1c")
    message = tb_message.get("1.0", "end-1c")
    if int(packet_size) > len(message):
        number_of_packets = 1
    else:
        number_of_packets = math.ceil(len(message) / int(packet_size))
    packet = 0
    num_of_packets = str(number_of_packets)
    dbg("Sending packet size...")
    client_socket.sendto(str.encode(num_of_packets), server_address)
    PRINT_INFO("Client: ", "Number of packets will be: ", num_of_packets)
    client_socket.recvfrom(1500)
    PRINT_INFO("Client: ", "Message Size: ", str(len(message)))
    dbg("I am going to send", number_of_packets, "packets")
    for i in range(int(number_of_packets)):
        packet = header(i, "20", message, packet_size)
        #send packet
        client_socket.sendto(str.encode(packet), server_address)
        PRINT_INFO("Client: ", "Sent packet: ", str(i))
        PRINT_INFO("Client: ", "Length: ", str(len(packet)))

        while True:
            data = None
            dbg("Cakam na ACK zo strany servera 10 sekund")
            client_socket.setblocking(0)
            ready = select.select([client_socket], [], [], 10)
            if ready[0]:
                dbg("cakam na recv")
                data = client_socket.recv(1500)
            dbg("Je po timeoute")

            dbg("Idem pozriet signalizacnu spravu od servera")
            if(data != None):
                data = data.decode()

            if data == None:
                dbg("Posielam ti packet znovu, nedostal som ack")
                PRINT_ERROR("Client: ", "I sent you again packet: ", str(i))
                PRINT_ERROR("Client: ", "Length: ", str(len(packet)))
                client_socket.sendto(str.encode(packet), server_address)
                continue

            if data == "-1":
                dbg("Posielam ti packet znovu, ak bol ten pred tym poskodeny")
                PRINT_ERROR("Client: ", "I sent you again packet: ", str(i))
                PRINT_ERROR("Client: ", "Length: ", str(len(packet)))
                packet = header(i, "20", message, packet_size)
                client_socket.sendto(str.encode(packet), server_address)
            if data == str(i):
                dbg("Idem na dalsi packet")
                break

        PRINT_INFO("Client: ", "Server recieved packet ", str(i))

    dbg("Now i finally sent all message packets")
    client_socket.sendto(str.encode("21"), server_address)
    PRINT_INFO("Client: ", "Succesfully sent message", " ")

# ================================================================
#   RECIEVE FILE
# ================================================================

def recieve_file(server_sock):
    dbg("now I am ready to recieve file, send me total num of packet first")

    # wait for initial message from client thats says he is going to send file and no of packets
    data = server_sock.recvfrom(1500)
    server_sock.sendto(str.encode(""), data[1])
    stored_id = ["" for x in range(int(data[0]))]
    stored_data = ["" for x in range(int(data[0]))]
    data_name = server_sock.recvfrom(1500)
    file_name = str(data_name[0].decode())
    file_path = "c:\\server\\" + file_name
    file_size = 0
    checksum_server = ""
    file = ""

    dbg("total num of packets is:", data[0])
    dbg("file name is:", file_name)
    server_sock.sendto(str.encode("25"), data[1]) # 25 from server to client to start sending packets
    PRINT_INFO("Server: ", "Total packet number from Client will be: ", str(data[0].decode()))
    PRINT_INFO("Server: ", "File name: ", file_name)
    PRINT_INFO("Server: ", "File Path where I store file: ", file_path)

    while True:
        #
        packet = server_sock.recvfrom(1500)
        p_type = decode_binary_string(packet[0][24:40])
        if p_type == "21": # or if packet id = total num of packets
            break
        checksum_server = check_sum_server_file(packet[0][0:24], packet[0][24:40], packet[0][40:72], packet[0][72:])

        if(int(checksum_server) != int(packet[0][40:72], 2)):
            dbg("Packet mi dosiel poskodeny, posli mi ho znovu")
            server_sock.sendto(str.encode("-1"), data[1])
            PRINT_ERROR("Server: ", "Recieved invalid packet: ", str(int(packet[0][0:24], 2)))
            PRINT_ERROR("Server: ", "Packet Length: ", str(len(packet[0])))
            continue;

        stored_data[int(packet[0][0:24], 2)] = packet[0][72:]
        dbg("Odosielam ACK")
        packet_no = str(int(packet[0][0:24], 2))
        server_sock.sendto(str.encode(packet_no), data[1])
        PRINT_INFO("Server: ", "Recieved packet: ", str(int(packet[0][0:24], 2)))
        PRINT_INFO("Server: ", "Packet Length: ", str(len(packet[0])))
    file = open(file_path, "wb")
    for d_pack in stored_data:
        file_size += len(d_pack)
        file.write(d_pack)
    file.close()
    PRINT_INFO("Server: ", "File recieved successfully", " ")
    PRINT_INFO("Server: ", "File name: ", file_name)
    PRINT_INFO("Server: ", "File Path: ", file_path)
    PRINT_INFO("Server: ", "File Size: ", str(file_size))


# ================================================================
#   SEND FILE
# ================================================================

def send_file(client_socket, server_address):
    PRINT_INFO("Client: ", "I am going to send file", " ")
    dbg("I am going to calculate file packet size and so on")
    client_socket.sendto(str.encode("18"), server_address)  # 18 - idem posielat file, tak sa priprav
    client_socket.recvfrom(1500)
    # wait for server to listen for messages
    time.sleep(1)

    packet_size = tb_packet_size.get("1.0", "end-1c")
    file_path = tb_message.get("1.0", "end-1c")
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    file = open(file_path, "rb")
    file_message = file.read();
    if int(packet_size) > 1428:
        packet_size = "1428"
    if int(packet_size) > int(file_size):
        number_of_packets = 1
    else:
        number_of_packets = math.ceil(int(file_size) / int(packet_size))
    packet = 0
    PRINT_INFO("Client: ", "File Name: ", file_name)
    PRINT_INFO("Client: ", "File Path: ", file_path)
    PRINT_INFO("Client: ", "File Size: ", str(file_size))
    num_of_packets = str(number_of_packets)
    dbg("Sending packet size...")
    client_socket.sendto(str.encode(num_of_packets), server_address)
    client_socket.recvfrom(1500)
    dbg("Sending file name...")
    client_socket.sendto(str.encode(file_name), server_address)
    client_socket.recvfrom(1500)

    dbg("I am going to send", number_of_packets, "packets")
    for i in range(int(number_of_packets)):
        packet = header_file(i, "20", file_message, packet_size)
        packet_data = file_message[i * int(packet_size):i * int(packet_size) + int(packet_size)]
        #send packet
        client_socket.sendto(str.encode(packet) + packet_data, server_address)
        PRINT_INFO("Client: ", "Sent packet: ", str(i))
        PRINT_INFO("Client: ", "Packet Length: ", str(len(packet) + len(packet_data)))
        while True:
            data = None
            dbg("Cakam na ACK zo strany servera 10 sekund")
            client_socket.setblocking(0)
            ready = select.select([client_socket], [], [], 10)
            if ready[0]:
                dbg("cakam na recv")
                data = client_socket.recv(1500)
            dbg("Je po timeoute")

            dbg("Idem pozriet signalizacnu spravu od servera")
            if(data != None):
                data = data.decode()

            if data == None:
                dbg("Posielam ti packet znovu, nedostal som ack")
                packet = header_file(i, "20", file_message, packet_size)
                packet_data = file_message[i * int(packet_size):i * int(packet_size) + int(packet_size)]
                PRINT_ERROR("Client: ", "Send again packet: ", str(i))
                PRINT_ERROR("Client: ", "Packet Length: ", str(len(packet) + len(packet_data)))
                client_socket.sendto(str.encode(packet) + packet_data, server_address)
                continue

            if data == "-1":
                dbg("Posielam ti packet znovu, ak bol ten pred tym poskodeny")
                packet = header_file(i, "20", file_message, packet_size)
                packet_data = file_message[i * int(packet_size):i * int(packet_size) + int(packet_size)]
                PRINT_ERROR("Client: ", "Send again packet: ", str(i))
                PRINT_ERROR("Client: ", "Packet Length: ", str(len(packet) + len(packet_data)))
                client_socket.sendto(str.encode(packet) + packet_data, server_address)
            if data == str(i):
                dbg("Idem na dalsi packet")
                break
        PRINT_INFO("Client: ", "Server recieved packet: ", str(i))

    dbg("Now i finally sent all message packets")
    final_packet = header_file(0, "21", "0", 1)
    client_socket.sendto(str.encode(final_packet), server_address)
    PRINT_INFO("Client: ", "Succesfully sent file: ", file_name)

# ================================================================
#   SERVER LOGIN
# ================================================================

def server_login():
    thread = threading.current_thread()
    thread.name = "ServerThread"
    dbg("Server starting...")
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    global server_port, client_loop
    server_port = tb_port.get("1.0", "end-1c")
    server_socket.bind(("0.0.0.0", int(server_port)))  # obsadi si port
    PRINT_INFO("Server: ", "Server is running on port: ", server_port)
    dbg("waiting recvfrom")
    address = server_socket.recvfrom(1500)
    dbg("recvform:", address[1])
    server_socket.sendto(str.encode("1"), address[1])
    PRINT_INFO("Server: ", "Initialized connection from address: ", str(address[1]))
    server_handler(server_socket, address[1])

    # CLOSE SOCKET AND SWITCH FOR CLIENT
    server_socket.shutdown(socket.SHUT_RDWR)
    server_socket.close()
    time.sleep(2)
    chb_server.deselect()
    chb_client.select()
    on_check_server()
    on_check_client()
    client_loop = True
    client_thread().start()

    dbg("server end")

# ================================================================
#   SERVER HANDLER
# ================================================================

def server_handler(server_socket, address):
    global server_loop, server_switch
    while server_loop:


        dbg("waiting recvfrom")
        data = server_socket.recvfrom(1500)  # tu caka, kym nepride message
        info = str(data[0].decode())
        dbg("recvform: ", info, data[1])

        if info == 'ahoj':
            server_socket.sendto(str.encode("1"), data[1])
            address = data[1]

        if info == '4':
            dbg("Keep alive received, Connection is on")
            PRINT_INFO("Server: ", "Keep Alive recieved, Connection is on", " ")
            server_socket.sendto(str.encode("4"), address)
            info = ''
        if info == '9':
            PRINT_INFO("Server: ", "I am going to swich as a Client", " ")
            server_socket.sendto(str.encode("9"), address)
            server_loop = False
        if info == '19':
            dbg("Client is going to send me message, so I am going to be ready")
            server_socket.sendto(str.encode("19"), address)
            recieve_message(server_socket)
        if info == '18':
            dbg("Client is going to send me file, so I am going to be ready")
            server_socket.sendto(str.encode("18"), address)
            recieve_file(server_socket)
        if info == '55':
            PRINT_INFO("Server: ", "Client disconnected...", " ")
        if server_switch:
            server_switch = False
            server_socket.sendto(str.encode("99"), address)
            server_loop = False
    dbg("server while end")

# ================================================================
#   Client Login
# ================================================================

def client_login():
    global server_loop, switch_roles_flag, stop_client, keep_alive_flag
    thread = threading.current_thread()
    thread.name = "ClientThread"
    dbg("Client starting...")
    flag = 1
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while flag:
        flag = 0
        try:
            address = tb_ip.get("1.0", "end-1c")
            port = tb_port.get("1.0", "end-1c")
            server_address = (address, int(port))
            client_socket.sendto(str.encode("ahoj"), server_address)

            dbg("server_address: ", server_address)
            client_socket.settimeout(60)
            data, address = client_socket.recvfrom(1500)
            data = data.decode()
            if data == "1":
                PRINT_INFO("Client: ", "Connected to address: ", str(server_address))
                keep_alive_flag = True
                keep_alive_thread(client_socket, server_address, 5).start()
                client_handler(client_socket, server_address)
                dbg("Connected to address:", server_address)
        except (socket.timeout, socket.gaierror) as e:
            print(e)
            PRINT_ERROR("Client: ", "Connection not working try again", " ")
            print("Connection not working try again")
            continue

    # CLOSE SOCKET AND SWITCH FOR SERVER
    client_socket.shutdown(socket.SHUT_RDWR)
    client_socket.close()
    if not stop_client:
        PRINT_INFO("Client: ", "Not Shut down", " ")
        switch_roles_flag = False
        server_loop = True
        chb_server.select()
        chb_client.deselect()
        on_check_server()
        on_check_client()
        server_thread().start()
    else:
        PRINT_INFO("Client: ", "Shuting Down", " ")
        stop_client = False
        keep_alive_flag = False
    dbg("client end")

# ================================================================
#   CLIENT HANDLER
# ================================================================

def client_handler(client_socket, server_address):
    dbg("Client")
    PRINT_INFO("Client: ", "Client handler", " ")
    global client_loop, switch_roles_flag, sending_message, keep_alive_stop, sending_file, server_loop, keep_alive_flag
    while client_loop:
        switch = 0
        client_socket.setblocking(1)
        ready = select.select([client_socket], [], [], 3)
        if ready[0]:
            switch = client_socket.recv(1500)
        if switch != 0:
            if switch.decode() == "99":
                switch_roles_flag = True
                server_loop = False
                break

        if stop_client:
            client_socket.sendto(str.encode("55"), server_address)
            break

        if sending_message:
            keep_alive_stop = True
            # wait keep alive to stop
            time.sleep(3)
            send_message(client_socket, server_address)
            sending_message = False
            keep_alive_stop = False
            time.sleep(3)

        if sending_file:
            keep_alive_stop = True
            # wait keep alive to stop
            time.sleep(3)
            send_file(client_socket, server_address)
            sending_file = False
            keep_alive_stop = False
            time.sleep(3)

        if switch_roles_flag:
            switch_roles_flag = False
            client_socket.sendto(str.encode("9"), server_address)
            data, address = client_socket.recvfrom(1500)
            data = data.decode()
            if data == "9":
                PRINT_INFO("Client: ", "Server is going to be a Client", " ")
                client_loop = False
        time.sleep(0.2)
    dbg("client handler end")

# ================================================================
#  START METHOD
# ================================================================

def start():
    if chb_client_checked.get():
        client_thread().start()
    elif chb_server_checked.get():
        server_thread().start()

# ****************************************************************
# *** PROGRAM START, INITIALIZE TKINTER COMPONENTS ***
# ****************************************************************
initialize()
# ****************************************************************