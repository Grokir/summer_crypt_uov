from UOV import uov_V

def test_uov():
  import galois
  q = 256
  GF256 = galois.GF(q)
  
  signer = uov_V()
  cpk, csk = signer.keygen()
  esk = signer.expand_SK(csk)

  msg = b"example message"
  sig = signer.sign(esk, msg)
  print("[TEST] Valid signature:", signer.verify(cpk, msg, sig))

  # Создаем неправильную подпись для того же сообщения
  if sig is not None:
    s, salt = sig

    wrong_s = s.copy()
    wrong_s[0] += GF256(1)  # Изменяем первый элемент подписи
    wrong_sig = (wrong_s, salt)
    print("[TEST] Invalid signature:", ( not signer.verify(cpk, msg, wrong_sig) ))
  else:
    print("[ERROR] Failed to generate initial signature")
