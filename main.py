import math
import sys
import threading
import time
from tkinter import *
import socket

global thread_status

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
    global tb_port, tb_ip, chb_server, chb_client, chb_server_checked, chb_client_checked, btn_start, tb_output_text, tb_packet_size, tb_message
    # WINDOW
    window = Tk()
    window.title("UDP Chat aplication")
    window.geometry("600x580")

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
    chb_server = Checkbutton(text="Server", variable=chb_server_checked, command=on_check_server)
    chb_server.place(x=300, y=50)
    chb_client = Checkbutton(text="Client", variable=chb_client_checked, command=on_check_client)
    chb_client.place(x=300, y=80)

    # BUTTONS
    btn_start = Button(window, text="Start", command=btn_start_click, width=10)
    btn_start.place(x=490, y=50)
    btn_switch = Button(window, text="Switch", command=btn_switch_click,  width=10)
    btn_switch.place(x=490, y=80)
    btn_message = Button(window, text="Message", command=btn_message_click)
    btn_message.place(x=470, y=530)
    btn_file = Button(window, text="File")
    btn_file.place(x=540, y=530)

    # MULTILINE TEXTBOX
    chatBox = Scrollbar(window)
    tb_output_text = Text(window, wrap='word', state='disabled', width=60, yscrollcommand=chatBox.set)
    tb_output_text.tag_configure("bold", font="Helvetica 10 bold")
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
    global switch_roles_flag, server_loop
    switch_roles_flag = True
    server_loop = False
    global server_port
    server_address = ("127.0.0.1", int(server_port))
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.sendto(str.encode("9"), server_address)
    client_socket.shutdown(socket.SHUT_RDWR)
    client_socket.close()

# ================================================================
# BUTTON MESSAGE CLICK
# ================================================================
def btn_message_click():
    global sending_message
    sending_message = True
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
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "Keep Alive is OFF" + '\n')
            tb_output_text.configure(state='disabled')
            break

        client_sock.sendto(str.encode('4'), server_addr)
        data = client_sock.recv(1500)
        info = str(data.decode())

        if info == '4':
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "Client: ", "bold")
            tb_output_text.insert('end', "Connection is working" + '\n')
            tb_output_text.configure(state='disabled')
            print("Connection is working")
        else:
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "Client: ", "bold")
            tb_output_text.insert('end', "Connection ended" + '\n')
            tb_output_text.configure(state='disabled')
            print("connection ended")
            break
        time.sleep(interval)
    keep_alive_end = True
    dbg("keep alive end")

# ================================================================
#   HEADER
# ================================================================
def header(id, type, data, p_size):
    id_size = 24
    packet = 0
    type_size = 16
    packet_id = format(id, 'b')
    packet_type = ''.join(format(i, '08b') for i in bytearray(str(type), encoding='utf-8'))
    temp_packet_data = data[id*int(p_size):id*int(p_size)+int(p_size)]
    packet_data = ''.join(format(i, '08b') for i in bytearray(str(temp_packet_data), encoding='utf-8'))
    if len(packet_id) < id_size:
        for i in range(id_size - len(packet_id)):
            packet_id = ''.join(('0', packet_id))

    packet = packet_id + packet_type + packet_data
    return packet

# ================================================================
#   RECIEVE MESSAGE
# ================================================================
def decode_binary_string(s):
    return ''.join(chr(int(s[i*8:i*8+8],2)) for i in range(len(s)//8))

def recieve_message(server_sock):
    dbg("now I am ready to recieve, send me total num of packet first")

    # wait for initial message from client thats says he is going to send message
    data = server_sock.recvfrom(1500)
    stored_id = ["" for x in range(int(data[0]))]
    stored_data = ["" for x in range(int(data[0]))]
    message = ""

    dbg("total num of packets is:", data[0])
    server_sock.sendto(str.encode("25"), data[1]) # 25 from server to client to start sending packets
    tb_output_text.configure(state='normal')
    tb_output_text.insert('end', "Server: ", "bold")
    tb_output_text.insert('end', "Client is going to send me" + str(data[0]) + " packets" + '\n')
    tb_output_text.configure(state='disabled')
    while True:
        # as a server store number of all packets into variable
        packet = server_sock.recvfrom(1500)
        p_type = str(packet[0].decode())
        if p_type == "21": # or if packet id = total num of packets
            break

        stored_data[int(packet[0][0:24], 2)] = decode_binary_string(packet[0][40:])
        server_sock.sendto(str.encode("20"), data[1])
        tb_output_text.configure(state='normal')
        tb_output_text.insert('end', "from Client: ", "bold")
        tb_output_text.insert('end', "Recieved packet: " + str(int(packet[0][0:24], 2)) + '\n')
        tb_output_text.configure(state='disabled')

    for data in stored_data:
        message += data
    tb_output_text.configure(state='normal')
    tb_output_text.insert('end', "Recieved Message: ", "bold")
    tb_output_text.insert('end', str(message) + '\n')
    tb_output_text.configure(state='disabled')



    # in while True loop wait for recieve message with type '20'
    # after recieved packet store data into array with id index
    # if server recieve message with type '21' break the loop
    # at out of while loop connect all data from array to string and output the message

# ================================================================
#   SEND MESSAGE
# ================================================================

def send_message(client_socket, server_address):
    dbg("I am going to calculate packet size and so on")
    client_socket.sendto(str.encode("19"), server_address)  # 19 - idem posielat spravu, tak sa priprav
    client_socket.recvfrom(1500)
    # wait for server to listen for messages
    time.sleep(1)

    packet_size = tb_packet_size.get("1.0", "end-1c")
    message = tb_message.get("1.0", "end-1c")
    if int(packet_size) > len(message):
        number_of_packets = len(message)
    else:
        number_of_packets = math.ceil(len(message) / int(packet_size))
    packet = 0
    num_of_packets = str(number_of_packets)
    dbg("Sending packet size...")
    client_socket.sendto(str.encode(num_of_packets), server_address)
    client_socket.recvfrom(1500)
    dbg("I am going to send", number_of_packets, "packets")
    for i in range(int(number_of_packets)):
        packet = header(i, "20", message, packet_size)
        #send packet
        client_socket.sendto(str.encode(packet), server_address)
        tb_output_text.configure(state='normal')
        tb_output_text.insert('end', "Client: ", "bold")
        tb_output_text.insert('end', "Sent packet " + str(i) + '\n')
        tb_output_text.configure(state='disabled')
        client_socket.recv(1500)
        tb_output_text.configure(state='normal')
        tb_output_text.insert('end', "Client: ", "bold")
        tb_output_text.insert('end', "Server recieved packet " + str(i) + '\n')
        # wait for ACK from server
        # if ACK was positive, continue
        # if ACK was negative, resend packet again
    dbg("Now i finally sent all message packets")
    client_socket.sendto(str.encode("21"), server_address)
    tb_output_text.configure(state='normal')
    tb_output_text.insert('end', "Client: ", "bold")
    tb_output_text.insert('end', "Succesfully sent message" + '\n')

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
    tb_output_text.configure(state='normal')
    tb_output_text.insert('end', "Server: ", "bold")
    tb_output_text.insert('end', "Server is running on port: " + server_port + '\n')
    tb_output_text.configure(state='disabled')
    dbg("waiting recvfrom")
    address = server_socket.recvfrom(1500)
    dbg("recvform:", address[1])
    server_socket.sendto(str.encode("1"), address[1])
    tb_output_text.configure(state='normal')
    tb_output_text.insert('end', "Established connection from address:" + str(address[1]) + '\n')
    tb_output_text.configure(state='disabled')
    dbg("Established connection from address:", address)
    server_handler(server_socket, address[1])

    # CLOSE SOCKET AND SWITCH FOR CLIENT
    server_socket.shutdown(socket.SHUT_RDWR)
    server_socket.close()
    time.sleep(1)
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
    global server_loop
    while server_loop:

        dbg("waiting recvfrom")
        data = server_socket.recvfrom(1500)  # tu caka, kym nepride message
        info = str(data[0].decode())
        dbg("recvform: ", info, data[1])

        if info == '4':
            dbg("Keep alive received, Connection is on")
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "Server: ", "bold")
            tb_output_text.insert('end', "Keep alive received, Connection is on" + '\n')
            tb_output_text.configure(state='disabled')
            server_socket.sendto(str.encode("4"), address)
            info = ''
        if info == '9':
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "Server: ", "bold")
            tb_output_text.insert('end', "I am going to swich as a Client" + '\n')
            tb_output_text.configure(state='disabled')
            server_socket.sendto(str.encode("9"), address)
            server_loop = False
        if info == '19':
            dbg("Client is going to send me message, so I am going to be ready")
            server_socket.sendto(str.encode("19"), address)
            recieve_message(server_socket)

    dbg("server while end")

# ================================================================
#   Client Login
# ================================================================

def client_login():
    global server_loop
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
                tb_output_text.configure(state='normal')
                tb_output_text.insert('end', "Client: ", "bold")
                tb_output_text.insert('end', "Connected to address:" + str(server_address) + '\n')
                tb_output_text.configure(state='disabled')
                keep_alive_thread(client_socket, server_address, 5).start()
                client_handler(client_socket, server_address)
                dbg("Connected to address:", server_address)
        except (socket.timeout, socket.gaierror) as e:
            print(e)
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "Client: ", "bold")
            tb_output_text.insert('end', "Connection not working try again", '\n')
            tb_output_text.configure(state='disabled')
            print("Connection not working try again")
            continue

    # CLOSE SOCKET AND SWITCH FOR SERVER
    client_socket.shutdown(socket.SHUT_RDWR)
    client_socket.close()
    server_loop = True
    chb_server.select()
    chb_client.deselect()
    on_check_server()
    on_check_client()
    server_thread().start()
    dbg("client end")

# ================================================================
#   CLIENT HANDLER
# ================================================================

def client_handler(client_socket, server_address):
    dbg("Client")
    global client_loop, switch_roles_flag, sending_message, keep_alive_stop
    while client_loop:
        if sending_message:
            keep_alive_stop = True
            # wait keep alive to stop
            #time.sleep(3)
            send_message(client_socket, server_address)
            sending_message = False
            keep_alive_stop = False

        if switch_roles_flag:
            switch_roles_flag = False
            client_socket.sendto(str.encode("9"), server_address)
            data, address = client_socket.recvfrom(1500)
            data = data.decode()
            if data == "9":
                tb_output_text.configure(state='normal')
                tb_output_text.insert('end', "Client: ", "bold")
                tb_output_text.insert('end', "Server is going to be a client" + '\n')
                tb_output_text.configure(state='disabled')
                client_loop = False
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