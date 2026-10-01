# Overview

Docker Security Audit reads saved Docker inspect JSON and reports selected configuration risks. It checks privileged mode, host namespace sharing, sensitive bind mounts, published ports, and whether the container declares a non-root user.

## A useful first exercise

Compare the supplied fixture with a copy that sets `Privileged` to `true` or `Config.User` to `root`. Then place both objects in one JSON list. The report should show each container separately and retain the distinct reasons for review.

This is a snapshot review with a small rule set. It does not inspect image vulnerabilities, secrets, effective runtime identities, capabilities, seccomp, or every mount type. A named user cannot be resolved to a UID without inspecting the image. A published port may be intentional; review its bindings and reachability in context.

[Back to the project guide](../README.md)
