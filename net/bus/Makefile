#
# Makefile for the Linux unix domain socket layer.
#

obj-$(CONFIG_BUS)	+= bus.o

bus-y			:= af_bus.o garbage.o
bus-$(CONFIG_SYSCTL)	+= sysctl_net_bus.o
