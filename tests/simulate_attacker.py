# tests/simulate_attacker.py
import time
import pyperclip

print("Simulating attack in 6 seconds. Put a sensitive value in your clipboard now (e.g., a crypto address).")
time.sleep(6)
orig = pyperclip.paste()
print("Original clipboard:", orig)
malicious = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # fake ETH address
pyperclip.copy(malicious)
print("Attacker replaced clipboard with:", malicious)
# attacker can replace again
time.sleep(2)
pyperclip.copy("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
print("Attacker replaced again.")
