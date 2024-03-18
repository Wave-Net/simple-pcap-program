import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff
import threading

# 패킷 캡처를 수행할 스레드를 저장하기 위한 변수
sniff_thread = None
# 패킷 캡처를 중단하기 위한 플래그
stop_sniffing_flag = False

def packet_handler(packet):
    # 패킷 요약 정보를 가져와서 문자열로 변환
    packet_summary = packet.summary()
    # 패킷 정보를 GUI에 추가
    text_area.insert(tk.END, packet_summary + '\n')

def start_sniffing():
    global sniff_thread
    global stop_sniffing_flag
    stop_sniffing_flag = False  # 캡처 시작 전 플래그 초기화

    # 패킷 캡처를 시작하는 함수
    def sniff_packets():
        sniff(prn=packet_handler, stop_filter=lambda x: stop_sniffing_flag)

    # 패킷 캡처를 실행할 새로운 스레드 생성
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.start()

def stop_sniffing():
    global stop_sniffing_flag
    # 스레드를 중지하기 위한 플래그 설정
    stop_sniffing_flag = True

# GUI 생성
root = tk.Tk()
root.title("Packet Sniffer")

# 텍스트 영역 생성
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
text_area.pack(expand=True, fill=tk.BOTH)

# 버튼을 담을 프레임 생성 및 중앙 정렬
button_frame = tk.Frame(root)
button_frame.pack(expand=True)

# 시작 버튼 생성 및 프레임에 추가
start_button = tk.Button(button_frame, text="Start Sniffing", command=start_sniffing)
start_button.pack(side=tk.LEFT, padx=10, pady=10)

# 중지 버튼 생성 및 프레임에 추가
stop_button = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing)
stop_button.pack(side=tk.LEFT, padx=10, pady=10)

# GUI 실행
root.mainloop()
