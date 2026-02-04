import pynvml
import time
import subprocess
import threading

def log_power(samples, duration=2.0, interval=0.01):
    pynvml.nvmlInit()
    handle = pynvml.nvmlDeviceGetHandleByIndex(0)
    start = time.time()
    while time.time() - start < duration:
        power = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000  # in Watts
        timestamp = time.time()
        samples.append((timestamp, power))
        time.sleep(interval)
    pynvml.nvmlShutdown()

# Start power logging in a thread
samples = []
logging_thread = threading.Thread(target=log_power, args=(samples,))
logging_thread.start()

# Run your compiled CUDA program
subprocess.run(["./packetProcess", "tenMillion.pcap"])

# Wait for power logging to finish
logging_thread.join()

# Save log
with open("highres_power_log.txt", "w") as f:
    for t, p in samples:
        f.write(f"{t},{p}\n")

# Compute average power
avg_power = sum(p for _, p in samples) / len(samples)
print(f"Average GPU Power (W): {avg_power:.2f}")