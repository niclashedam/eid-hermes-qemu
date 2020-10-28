# eid-hermes: Docker and QEMU

## Introduction

This folder contains Docker and QEMU related files for testing the
[eid-hermes][1] (virtual) device. It builds and spins up a docker
container that contains a QEMU based VM that includes the hermes
device model.

## Quick Start

1. ```./gen-images``` - pulls the Ubuntu Focal cloud image and
generates a cloud-init based configuration disk for it, which installs
some base packages and runs an [ansible playbook][2] to setup the xdma driver and
other programs. Also generates a blank image for the NVMe SSD device model.
**NOTE** that you only have to do this step once. The rootfs will presist
across container builds unless you rerun this script. If you do rerun this
script you will lose any local changes you have made to the rootfs.

3. ```docker-compose up --build``` - optionally builds and then spins
up a docker container that runs the eid-hermes based VM. It also opens
port 2222 for ssh into the VM from outside the container. Note you can
add a ``-d`` to this command to run the container as a background
task. **Note that you will want to change the HERMES_QEMU_REF argument
to point to the commit REF or branch you care about. Do this in
docker-compose.yml**.

4. ```ssh -p 2222 hermes@localhost``` - note you might have to redo
your known_hosts each time you regenerate the images. The password is
`zeus`.

## Future Work

1. Add support for optionally passing QEMU a specific kernel to use in
the VM via the -kernel command line argument.

[1]: https://github.com/Eideticom/eid-hermes/
[2]: https://github.com/Eideticom/eid-hermes/blob/master/ansible/hermes.yml
