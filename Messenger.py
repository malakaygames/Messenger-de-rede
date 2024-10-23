import socket
import threading
import tkinter as tk
from io import BytesIO

import requests
from PIL import ImageTk, Image


# Função para receber mensagens
def receive_messages():
    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            message = data.decode('utf-8')
            conversation_text.config(state=tk.NORMAL)
            conversation_text.insert(tk.END, f"{addr[0]}: {message}\n")
            conversation_text.config(state=tk.DISABLED)
            ip_suffix = addr[0].split('.')[-1]  # Obtém o último octeto do IP
            ip_entry.delete(0, tk.END)  # Limpa o campo de entrada de IP
            ip_entry.insert(tk.END,
                            ip_suffix)  # Preenche o campo de entrada de IP com o último octeto do IP do remetente
            if not ip_exists_in_contacts(addr[0]):  # Verifica se o IP já está na lista de contatos
                ip_listbox.insert(tk.END, addr[0])  # Adiciona o IP à lista de contatos
                ip_listbox.see(tk.END)  # Rola a lista de contatos para exibir o novo IP recebido
        except Exception as e:
            print(e)
            break


# Função para verificar se o IP já está na lista de contatos
def ip_exists_in_contacts(ip):
    return ip in ip_listbox.get(0, tk.END)


# Função para enviar mensagens
def send_message():
    ip_suffix = ip_entry.get()
    if ip_suffix:
        try:
            dest_ip = "10.20.10." + ip_suffix
            message = message_entry.get("1.0", tk.END).strip()  # Obtém e limpa o texto do campo de texto
            if message:
                conversation_text.config(state=tk.NORMAL)
                conversation_text.insert(tk.END, f"Você: {message}\n")
                conversation_text.config(state=tk.DISABLED)
                client_socket.sendto(message.encode('utf-8'), (dest_ip, port))
                message_entry.delete("1.0", tk.END)  # Limpa o campo de entrada de mensagem
        except Exception as e:
            print(e)


# Função para selecionar um contato na lista de contatos
def select_contact(event):
    widget = event.widget
    index = widget.curselection()[0]  # Obtém o índice do item selecionado na lista
    ip = widget.get(index)  # Obtém o IP selecionado
    ip_suffix = ip.split('.')[-1]  # Obtém o último octeto do IP
    ip_entry.delete(0, tk.END)  # Limpa o campo de entrada de IP
    ip_entry.insert(tk.END, ip_suffix)  # Preenche o campo de entrada de IP com o último octeto do IP


# Função para baixar e redimensionar a imagem
def get_resized_image(url):
    response = requests.get(url)
    image2 = Image.open(BytesIO(response.content))
    return ImageTk.PhotoImage(image2)


# Configurações de rede
port = 12345  # Porta para comunicação
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('0.0.0.0', port))  # Ouvir em todas as interfaces de rede
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Interface gráfica
root = tk.Tk()
root.title("Mensageiro de Rede")
root.configure(bg="#f0f0f0")  # Define a cor de fundo da janela

# Adiciona a imagem
image_url = "https://i.ibb.co/JHjtDcj/logo.png"
image = get_resized_image(image_url)
image_label = tk.Label(root, image=image, bg="#f0f0f0")
image_label.grid(row=0, column=0, sticky="nw", padx=10, pady=10)

# Frame para os contatos
contacts_frame = tk.Frame(root, bg="#f0f0f0")
contacts_frame.grid(row=1, column=0, padx=10, pady=10)

ip_list_label = tk.Label(contacts_frame, text="Contatos:", bg="#f0f0f0")
ip_list_label.pack()

ip_listbox = tk.Listbox(contacts_frame, height=15, width=20)
ip_listbox.pack()

# Evento para selecionar um contato ao dar dois cliques
ip_listbox.bind("<Double-Button-1>", select_contact)

# Frame para a conversa
conversation_frame = tk.Frame(root, bg="#f0f0f0")
conversation_frame.grid(row=0, column=1, rowspan=2, padx=10, pady=10)

ip_label = tk.Label(conversation_frame, text="IP do Destino:", bg="#f0f0f0")
ip_label.pack()

ip_entry = tk.Entry(conversation_frame, width=15)
ip_entry.pack()

message_label = tk.Label(conversation_frame, text="Digite a mensagem:", bg="#f0f0f0")
message_label.pack()

message_entry = tk.Text(conversation_frame, height=5, width=50)  # Aumenta o campo de texto
message_entry.pack()

send_button = tk.Button(conversation_frame, text="Enviar Mensagem", command=send_message)
send_button.pack()

conversation_label = tk.Label(conversation_frame, text="Conversa:", bg="#f0f0f0")
conversation_label.pack()

conversation_text = tk.Text(conversation_frame, height=20, width=50, state=tk.DISABLED)
conversation_text.pack()

# Binding da tecla Enter para enviar mensagem
root.bind("<Return>", send_message)

# Thread para receber mensagens
receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()

# Mantém a janela aberta
root.mainloop()
