# Overview

Docker Security Audit reads saved Docker inspect JSON and reports selected configuration risks. It checks privileged mode, host namespace sharing, sensitive bind mounts, published ports, and whether the container declares a non-root user.

The source code in `src/` contains the implementation.
