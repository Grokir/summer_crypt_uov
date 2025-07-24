from UOV import uov
from tests import *


def timer_decoration(txt:str, func)->None:
  from datetime import datetime
  
  start_time = datetime.now()
  print(f"\n\n[*] {txt}")
  print(f"[!] Start time:           {start_time.strftime("%Y-%m-%d %H:%M:%S")}\n")
  
  func()
  
  end_time = datetime.now()
  print(f"\n[!] End time:             {end_time.strftime("%Y-%m-%d %H:%M:%S")}")
  print(f"[+] Summary running time: {end_time - start_time}")


def main():
  timer_decoration( "Test UOV-Ip",  test_uov_Ip  )
  timer_decoration( "Test UOV-Is",  test_uov_Is  )
  timer_decoration( "Test UOV-III", test_uov_III )
  timer_decoration( "Test UOV-V",   test_uov_V   )
  
  # timer_decoration("Test Attack on UOV-Ip", test_attack_UOV_Ip)
  


if __name__ == "__main__":
  main()
