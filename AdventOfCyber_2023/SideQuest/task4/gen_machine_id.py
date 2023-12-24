machine_id = b""
for filename in "machine_id", "proc_kernel_boot_id":
    try:
        with open(filename, "rb") as f:
            value = f.readline().strip()
    except OSError:
        continue
    if value:
        machine_id += value
        break
try:
    with open("proc_self_cgroup", "rb") as f:
        machine_id += f.readline().strip().rpartition(b"/")[2]
except OSError:
    pass
print(machine_id)