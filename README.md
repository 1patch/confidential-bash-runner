# Confidential Bash runner

A small generic Bash execution service intended for a dedicated Tinfoil CVM.
The trusted supervisor runs each command as UID 1000 in a separate gVisor sandbox.
No application backend, customer data or private signing key is included here.

The service accepts one-use Ed25519 grants binding a tenant, command digest,
timeout and boot nonce. Its coordinator must verify the exact measured release
and use encrypted HTTP body transport through Tinfoil's shim. Publishing or
running this image alone does not establish confidential execution.

Limits: 100 temporary workspaces, four concurrent commands, 64 MiB and 8,192
inodes per workspace; 512 MiB RAM, no swap, one CPU, 64 host tasks and 60 seconds
per command. Tenant networking is disabled. Files survive commands but expire
after ten minutes idle or when the CVM is replaced. Completed idle workspaces
are safely unmounted and removed, allowing successive owners beyond the first
100 while retaining the memory bound. Active or uncertain workspaces are never
reassigned. Uncertain commands are quarantined and never replayed.
The coordinator that issues grants can see command inputs and outputs.

The supervisor requires an isolated, privileged container with a private cgroup
v2 namespace. Its entrypoint enables verified sibling CPU, memory and PID
controllers. Tenant code receives none of these administrative capabilities.
Use a dedicated CVM: the supervisor has administrative authority over that CVM.

Build and exercise the Linux sandbox:

```sh
docker build --build-arg TARGETARCH=amd64 --target bash-test -f deploy/confidential/Dockerfile -t bash-test .
docker run --rm --privileged --cgroupns=private --tmpfs /run:rw,nosuid,nodev,size=8g -e CONFIDENTIAL_BASH_LINUX_TEST=1 bash-test
```

The automated Linux tests use synthetic data. Passing them is not evidence of
Tinfoil hardware attestation or measured performance on confidential hardware.
