from UOV import uov
from tests import *
from datetime import datetime


def timer_decoration(txt:str, func)->None:
  start_time = datetime.now()
  print(f"\n[*] {txt}")
  print(f"[!] Start time:           {start_time.strftime("%Y-%m-%d %H:%M:%S")}")
  func()
  end_time = datetime.now()
  print(f"[!] End time:             {end_time.strftime("%Y-%m-%d %H:%M:%S")}")
  print(f"[+] Summary running time: {end_time - start_time}")


def main():
  # print("[*] Test UOV-V")
  # test_uov_V()

  # timer_decoration("Test UOV-Ip", test_uov_Ip)
  # timer_decoration("Test UOV-III", test_uov_III)
  # timer_decoration("Test UOV-V", test_uov_V)
  
  timer_decoration("Test Attack on UOV-Ip", test_attack_UOV_Ip)
  


if __name__ == "__main__":
  main()
