import signal
import subprocess

otp = subprocess.Popen(['./otp', '0'], stderr=subprocess.STDOUT)
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)



