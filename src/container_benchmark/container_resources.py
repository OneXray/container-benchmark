"""Uniform VM resources for every benchmark-owned container."""

CPUS = 5
MEMORY = "8G"
MEMORY_BYTES = 8 * 1024**3
ARGUMENTS = ("--cpus", str(CPUS), "--memory", MEMORY)
