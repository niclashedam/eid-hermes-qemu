# Dockerfile-hermes
# -----------------
#
# A Dockerfile for working on the eid-hermes QEMU project. For more
# information on the eid-hermes project see:
#
# https://github.com/Eideticom/eid-hermes
#
# This Dockerfile git clones the hermes branch of eid-hermes-qemu and
# does a minimal configuration and build of the x86 system
# emulator. It then uses a cloud-init based rootfs to boot up a VM
# with an eid-hermes device and a fake NVMe SSDs.
#
# We create a sudoer called hermes with password zeus (his father) for
# the VM. We also install some packages inside the VM that will be
# useful for working on the eid-hermes device.
#
# (c) Stephen Bates, Eideticom, 2020

  # Start from Ubuntu Focal.

FROM ubuntu:focal
MAINTAINER Stephen Bates <stephen@eideticom.com>

  # Update the packages and install a bunch of useful things that we
  # will need in the subsequent steps. Note the noninteractive is
  # important!

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && apt-get install -y \
  autoconf automake autotools-dev curl libmpc-dev libmpfr-dev libgmp-dev \
  gawk build-essential bison flex texinfo gperf libtool patchutils bc \
  zlib1g-dev libexpat-dev git iproute2 bridge-utils emacs-nox python \
  python3 libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev \
  libnfs-dev libiscsi-dev tree wget

  # Setup some environment variables including our top-level
  # folder. Make sure we create this top-level folder.

ENV HERMES /opt/hermes
RUN mkdir -p $HERMES

  # Clone the ubpf library so QEMU will build in a way that supports
  # the hermes device model.

RUN mkdir -p ${HERMES}/ubpf
WORKDIR ${HERMES}/ubpf
RUN git init && \
  git remote add origin https://github.com/iovisor/ubpf.git && \
  git fetch origin && \
  git checkout -b hermes 0014f298be3e2a63
RUN make -C vm && \
  make -C vm install

  # Clone QEMU at the point we want and then configure and build
  # it. Pass in this REF as an argument.

ARG HERMES_QEMU_REF
RUN mkdir -p ${HERMES}/qemu
WORKDIR ${HERMES}/qemu
RUN git init && \
  git remote add eid https://github.com/Eideticom/eid-hermes-qemu.git && \
  git fetch eid $HERMES_QEMU_REF --depth=1 && \
  git checkout $HERMES_QEMU_REF
RUN mkdir -p _build
WORKDIR _build
RUN ../configure --target-list=x86_64-softmmu --prefix=/usr/local/ \
  --enable-trace-backends=simple --enable-libubpf && \
  make -j $(nproc) && \
  make install

  # Now set up the image files folder needed to run the hermes
  # VM. Note that we will do a volume mount on the host so that these
  # images persist across docker container spin-ups.

RUN mkdir -p ${HERMES}/images

  # Set the entry-point for this image to spin up QEMU. Also open the
  # requested SSH port (currently 2222) so we can ssh in to this VM
  # from the host outside the container.

WORKDIR ${HERMES}
ENTRYPOINT qemu-system-x86_64 -nographic \
      -enable-kvm \
      -trace enable='hermes*' \
      -m 4096 -smp 4 \
      -drive file=${HERMES}/images/hermes-vm.qcow2,format=qcow2 \
      -drive file=${HERMES}/images/hermes-vm-seed.qcow2,format=raw,media=cdrom \
      -net nic,model=virtio -net user,hostfwd=tcp::2222-:22 \
      -device hermes \
      -drive file=${HERMES}/images/nvme.qcow2,id=nvme1,if=none -device nvme,drive=nvme1,serial=nvme1,cmb_size_mb=0
